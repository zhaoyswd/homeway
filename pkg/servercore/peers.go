package servercore

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// 设备表（2026-09-20 起，取代按 WG 公钥为键的动态 peer 表）。
//
// 为什么要换代：客户端身份从前是「每隧道世代一把临时密钥」，而旧表以公钥为键、按「上次注册时间」
// 做 LRU —— 于是每次重连都占一个新名额，表满后淘汰的永远是「注册最老」的那条，而它恰好可能是
// 一台长连、仍在线的设备（老 ≠ 死）。实测：A 长连 + B 重连 8 次 ⇒ A 被 RemovePeer，黑洞 2–4 分钟。
//
// 现在的语义（与 openspec/changes/device-identity-persist 的 spec 一一对应）：
//   - 键 = 注册报文里的设备标签 devTag（设备本地生成、跨连接稳定，见 pkg/proto/reg.go）；
//   - 同设备重复注册只刷新 lastReg；同 devTag 换公钥 = 身份轮换 ⇒ 原子替换 device 侧 peer 配置；
//   - 表满只淘汰**超过活跃宽限期（grace）未刷新**的设备中最旧的一条；全部活跃则拒绝新设备
//     （ErrTableFull，绝不淘汰在线设备）；
//   - TTL 周期回收长期不活跃设备（RunGC）；
//   - 登记/刷新/轮换/淘汰/拒绝/回收各打一行日志（dev/pub 短指纹 + 隧道地址 + n/cap + 原因）。
//
// 隧道地址仍由 (secret, pubkey) 两端各自派生（proto.DeriveTunnelIP）：身份稳定 ⇒ 地址稳定；
// 身份轮换时地址随新公钥变化，由替换路径处理。
type PeerConfig struct {
	Pubkey   [32]byte
	PSK      [32]byte
	TunnelIP netip.Addr // 100.64.0.0/16 内 /32
	// TunIP 应用面地址（l3-exit-intercept D4 的第二派生地址）：
	// L3 transit 的源/回程目的，与 TunnelIP 一起登记 allowed_ip。
	TunIP netip.Addr
}

// Configurer 把表项落到 WG device（生产实现包 IpcSet；测试用 fake）。
type Configurer interface {
	AddPeer(pc PeerConfig) error
	RemovePeer(pubkey [32]byte) error
}

// Action 一次注册/回收对设备表造成的变化（测试断言与日志口径）。
type Action string

const (
	ActionAdded     Action = "add"
	ActionRefreshed Action = "refresh"
	ActionRotated   Action = "rotate"
	ActionExpired   Action = "expire"
)

// Result 一次登记/回收的结果快照。
type Result struct {
	DevTag   proto.DevTag
	Pubkey   [32]byte
	TunnelIP netip.Addr
	Action   Action
	// 轮换时填充（旧公钥/旧隧道地址），日志用。
	OldPubkey [32]byte
	OldIP     netip.Addr
	// Idle = 距上一次活跃（刷新/轮换/回收时填充）。
	Idle time.Duration
}

var (
	// ErrNoToken reg 报文没有任何已知 token secret 能验通。
	ErrNoToken = errors.New("peers: reg 验证失败（无匹配 token）")
	// ErrTableFull 表满且所有设备都在活跃宽限期内刷新过——拒绝新设备，绝不淘汰在线设备。
	ErrTableFull = errors.New("peers: 设备表已满且没有超过活跃宽限期的失联设备")
	// ErrTunnelIPConflict 派生地址与在表设备的地址撞车（FIX-66）：**显式拒绝注册**。
	// 原实现退到池地址并造一条设备记录——但客户端只会用它自己派生的地址发包，池地址
	// 永远收不到它的流：那条记录是「注定不通」的，还占了表位与 allowed_ip 名额。
	ErrTunnelIPConflict = errors.New("peers: 派生隧道地址与在表设备冲突（请在该设备上重置本机身份后重连）")
	// ErrTokenRevoked 凭证验通但已在吊销表内（FIX-64）：与 ErrNoToken 分开归因——
	// 「token 已被吊销」是可行动的（重新粘贴新 token），「无匹配 token」多半是抄错。
	ErrTokenRevoked = errors.New("peers: token 已被吊销（请向出口索取新 token 后重新粘贴）")
)

// DeviceConfig 设备表参数（零值走默认）。
type DeviceConfig struct {
	MaxDevices int           // <=0 = 32
	TTL        time.Duration // **0 = 关闭 TTL 回收**（缺省 7d 由 config/flag 层落值，FIX-62；<0 视同关）
	Grace      time.Duration // <=0 = 10 分钟（表满淘汰门槛）
	// Revoked 凭证吊销判定（FIX-64；nil = 无吊销面）。构造期 secrets 是静态集，
	// 吊销由这个**活钩子**在每次验证时复查——出口侧接台账吊销表的跟随读
	// （internal/server 的 revokedFollower），让「吊销」无需重启即时生效。
	Revoked func(secret [32]byte) bool
}

// 注册拒绝归因（FIX-64：按原因计数，摘要行与细节行都带累计值——「有多少设备/
// 哪种原因被挡在门外」不必翻日志逐条数）。
const (
	RejNoToken   = "no-token"    // reg 报文没有已知 token 能验通（抄错/旧凭证已换）
	RejRevoked   = "revoked"     // 凭证验通但在吊销表内
	RejTableFull = "table-full"  // 表满且无失格设备可淘汰（绝不淘汰在线设备）
	RejConflict  = "ip-conflict" // 派生隧道地址与在表设备撞车
)

const (
	defaultMaxDevices = 32
	defaultTTL        = 7 * 24 * time.Hour
	defaultGrace      = 10 * time.Minute
)

type dentry struct {
	dev proto.DevTag
	pub [32]byte
	psk [32]byte
	ip  netip.Addr
	// tunIP：第二派生地址（应用面 /32，review #16）。占用检测必须把**全部设备的
	// 两个地址**当一个集合看——WG 的 allowedips 是全局前缀表，任何一个 /32 撞车
	// 都会让其中一个设备的该地址方向错路由（此前只查 ip，应用面地址冲突静默通过）。
	tunIP     netip.Addr
	lastReg   time.Time
	createdAt time.Time
}

// DeviceTable 以设备标签为键的动态设备表（wg-native-stack tasks 3.2 的换代）。
// secrets 单轨（host-registry-daemon D7）：构造期给全量、之后不再有热重读——
// `Secrets()` 仅启动期调用、`IssueToken` 先于建表入集（签发永远先于建表），
// 热重载无生产场景。
type DeviceTable struct {
	mu      sync.Mutex
	cfg     Configurer
	secrets [][32]byte
	logf    func(format string, args ...any)
	// sumf：摘要级日志（events.log）——注册拒绝是「需要人看一眼」的事件，
	// 每类原因每进程只大声一次（其后累计值进细节行），避免凭证刷注册打爆摘要。
	sumf    func(format string, args ...any)
	revoked func(secret [32]byte) bool

	// rejX：按原因的拒绝计数（累计；细节行与摘要行都读它）。
	rejMu   sync.Mutex
	rejOnce map[string]bool
	rejCnt  map[string]uint64

	max   int
	ttl   time.Duration
	grace time.Duration

	entries map[proto.DevTag]*dentry

	// opCh / opStart：设备配置操作（AddPeer/RemovePeer=IpcSet）的**FIFO 单消费者队列**。
	// 这些操作拿的是 wireguard device 的内部锁——**绝不能在 ReceiveFunc 里同步等它**：
	// device.Close 的收工会等 ReceiveFunc 退出、而 IpcSet 在等 device 的锁，互为环就是
	// 死锁（实测：注册恰好落在收工窗口时整套测试挂死）。所以丢到后台执行、调用方只做
	// 有界等待。
	// ⚠️ 必须是**队列**而不是"每次起一个 goroutine 抢一把 mutex"（review 复审 a2）：
	// Go 的 mutex 不保证 FIFO，淘汰路径的 RemovePeer 与新登记的 AddPeer 可能乱序执行，
	// 留下"表里已登记、device 里没有该 peer"的静默分歧。单消费者串行 ⇒ 提交顺序=执行顺序。
	opCh    chan devOp
	opStart sync.Once
	// pending：未执行完的设备操作数（FIX-67 状态面）。
	pending atomic.Int64
}

// devOp：一次设备配置操作（fn 执行完毕即 close(done)）。
type devOp struct {
	fn   func()
	done chan struct{}
}

// devOpTimeout：applyDeviceOp 的等待上界。正常 IpcSet 是微秒级；超时只发生在
// 「设备正在收工」的窗口——放弃等待让 ReceiveFunc 能返回（操作仍在队列里按序执行，
// 收工后自然完成或随设备一起消亡）。var 而非 const：单测压缩到毫秒级。
var devOpTimeout = 2 * time.Second

// applyDeviceOpAsync 只入队、**不等完成**（FIX-67：注册路径专用）。接收路径
// （WG 收包 goroutine）此前同步等完成，devOpTimeout 的界意味着最坏 2s 的**全局停包**
// （两条 op 串行或锁竞争时更长）——同机其它设备的流量、握手全被这条 goroutine 拖住。
// 代价与补偿：注册应答先于 AddPeer 落地发出，而 client 的 WG 握手本就靠 device 里有
// 这个 peer 才能完成 ⇒ 首个握手 initiation 可能被丢、由 WG 自己的重试兜住（毫秒级
// 完成时无感）；换来的是停包窗口从「全员」缩到「只此一台的首个握手」。
//
// 失败面：入队超时（队列满 128）仍大声告警——那才是真正会产生「表与 device 不一致」
// 的路径（完成超时不再影响调用方，操作仍在队列里按序执行）。
func (t *DeviceTable) applyDeviceOpAsync(op func(), what string) {
	t.opStart.Do(func() {
		t.opCh = make(chan devOp, 128)
		go func() {
			for o := range t.opCh {
				o.fn()
				close(o.done)
			}
		}()
	})
	t.pending.Add(1)
	timer := time.NewTimer(devOpTimeout)
	defer timer.Stop()
	select {
	case t.opCh <- devOp{fn: func() { op(); t.pending.Add(-1) }, done: make(chan struct{})}:
	case <-timer.C:
		t.pending.Add(-1)
		t.logf("peer: ⚠️ 设备配置操作排队超时（%v，%s）——本次**未执行**，device 与设备表可能不一致（等待下一条注册/重连对账收敛）", devOpTimeout, what)
	}
}

// PendingOps 尚未执行完的设备配置操作数（FIX-67 状态面：注册已应答但 device 写入
// 未落地时 >0；诊断/测试观察用）。
func (t *DeviceTable) PendingOps() int64 { return t.pending.Load() }

// applyDeviceOp：把操作提交到 FIFO 队列并在有限时间内等待完成。
//
// 两种超时语义不同，都必须留痕（review 复审 a2：旧实现超时后返回值与日志都像成功）：
//   - 入队超时：操作**从未执行** ⇒ device 与设备表可能不一致，大声告警；
//   - 完成超时：操作仍排在队列里按序执行，只是调用方不再等（设备收工窗口的锁竞争）。
func (t *DeviceTable) applyDeviceOp(op func()) {
	t.opStart.Do(func() {
		t.opCh = make(chan devOp, 128)
		go func() {
			for o := range t.opCh {
				o.fn()
				close(o.done)
			}
		}()
	})
	o := devOp{fn: op, done: make(chan struct{})}
	timer := time.NewTimer(devOpTimeout)
	defer timer.Stop()
	select {
	case t.opCh <- o:
	case <-timer.C:
		t.logf("peer: ⚠️ 设备配置操作排队超时（%v）——本次**未执行**，device 与设备表可能不一致（等待下一条注册/重连对账收敛）", devOpTimeout)
		return
	}
	select {
	case <-o.done:
	case <-timer.C:
		t.logf("peer: ⚠️ 设备配置操作 %v 未完成（设备收工中的锁竞争）—— 调用方不再等待（操作仍在队列里按序执行）", devOpTimeout)
	}
}

// NewDeviceTable 建表（cfg 零值走默认：32 台 / 7 天 / 10 分钟宽限）。
func NewDeviceTable(cfg Configurer, secrets [][32]byte, opt DeviceConfig) *DeviceTable {
	if opt.MaxDevices <= 0 {
		opt.MaxDevices = defaultMaxDevices
	}
	if opt.Grace <= 0 {
		opt.Grace = defaultGrace
	}
	return &DeviceTable{
		cfg:     cfg,
		secrets: secrets,
		logf:    logf,
		sumf:    logf, // 未注入时与细节同口（不丢信息）
		revoked: opt.Revoked,
		rejOnce: map[string]bool{},
		rejCnt:  map[string]uint64{},
		max:     opt.MaxDevices,
		ttl:     opt.TTL,
		grace:   opt.Grace,
		entries: make(map[proto.DevTag]*dentry, opt.MaxDevices),
	}
}

// SetSummaryLogger 注入摘要级日志（events.log；FIX-64 的拒绝摘要行用）。
func (t *DeviceTable) SetSummaryLogger(fn func(format string, args ...any)) {
	if fn == nil {
		return
	}
	t.mu.Lock()
	t.sumf = fn
	t.mu.Unlock()
}

// rejectCount / noteReject：按原因的累计拒绝计数与「首次大声」摘要。
// 摘要行每类原因每进程只出一次（其后同类拒绝只进细节行，避免刷屏）；计数不受
// 节流影响，细节行总携带最新累计值。
func (t *DeviceTable) noteReject(reason string, format string, args ...any) {
	// 日志口与 SetLogger/SetSummaryLogger 一样是「装配期一次设定」的既定约定
	//（既有各 logf 调用点同样裸读），这里不额外加锁。
	logf, sumf := t.logf, t.sumf
	t.rejMu.Lock()
	t.rejCnt[reason]++
	n := t.rejCnt[reason]
	first := !t.rejOnce[reason]
	if first {
		t.rejOnce[reason] = true
	}
	t.rejMu.Unlock()
	if first && sumf != nil {
		sumf("⚠️ 注册被拒（原因=%s，累计 %d）——%s", reason, n, rejectHint(reason))
	}
	if logf != nil {
		logf(format+"（原因=%s，累计 %d）", append(args, reason, n)...)
	}
}

// RejectCounts 按原因的累计拒绝数快照（诊断/测试）。
func (t *DeviceTable) RejectCounts() map[string]uint64 {
	t.rejMu.Lock()
	defer t.rejMu.Unlock()
	out := make(map[string]uint64, len(t.rejCnt))
	for k, v := range t.rejCnt {
		out[k] = v
	}
	return out
}

// rejectHint：拒绝原因的可行动提示（摘要行文案）。
func rejectHint(reason string) string {
	switch reason {
	case RejRevoked:
		return "该凭证已被吊销。向出口索取新 token（`homeway serve restart` 会铸出新凭证）后重新粘贴；旧 token 不再可用"
	case RejNoToken:
		return "token 抄错或来自别的出口？核对该 token 并在 App 里重新粘贴"
	case RejTableFull:
		return "设备表已满且在线设备不可淘汰；等待失联设备过期或调大 --max-peers"
	case RejConflict:
		return "派生地址与在表设备冲突；在该手机上「重置本机身份」后重连"
	}
	return "见细节日志"
}

// SetLogger 注入正式日志（homewayd 装配）；不注入则用包内兜底。
func (t *DeviceTable) SetLogger(fn func(format string, args ...any)) {
	if fn == nil {
		return
	}
	t.mu.Lock()
	t.logf = fn
	t.mu.Unlock()
}

// currentSecrets 读构造期 secrets 全集（verify 用）。
func (t *DeviceTable) currentSecrets() [][32]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.secrets
}

// verify 逐一试构造期 secrets 全集，返回 (公钥, 设备标签, 命中的 secret)。
// 单轨（D7）：未命中即 ErrNoToken——无热重读分支；重签发的 token 随出口重启
// （或下个发版窗口的部署）进构造期集合。
func (t *DeviceTable) verify(reg []byte, now time.Time) (pubkey [32]byte, devTag proto.DevTag, secret [32]byte, err error) {
	revoked := t.revokedHook()
	for _, sec := range t.currentSecrets() {
		if pk, dt, verr := proto.VerifyReg(sec, reg, now, 0); verr == nil {
			// 吊销复查（FIX-64）：构造期 secrets 是静态集，吊销表由活钩子带进来
			//（出口侧 = 台账吊销表的跟随读，秒级生效、无需重启）。命中即拒——
			// 归因与「没有已知 token」分开，便于手机端与运维分清「吊销」与「抄错」。
			if revoked != nil && revoked(sec) {
				return pubkey, devTag, secret, ErrTokenRevoked
			}
			return pk, dt, sec, nil
		}
	}
	return pubkey, devTag, secret, ErrNoToken
}

// revokedHook 读吊销钩子（锁内取函数值；钩子自身线程安全）。
func (t *DeviceTable) revokedHook() func(secret [32]byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.revoked
}

// Register 验证 reg 报文并按设备标签登记/刷新/轮换。返回本次动作快照（日志与测试用）。
func (t *DeviceTable) Register(reg []byte, now time.Time) (Result, error) {
	pubkey, devTag, secret, err := t.verify(reg, now)
	if err != nil {
		// 失败归因进计数与摘要（FIX-64）：devTag 拿不到（验证不过），只记原因。
		switch {
		case errors.Is(err, ErrTokenRevoked):
			t.noteReject(RejRevoked, "peer: ! reject reason=revoked")
		case errors.Is(err, ErrNoToken):
			t.noteReject(RejNoToken, "peer: ! reject reason=no-token")
		default:
			t.noteReject(RejNoToken, "peer: ! reject reason=verify（%v）", err)
		}
		return Result{}, err
	}
	psk := proto.DerivePSK(secret)

	t.mu.Lock()
	defer t.mu.Unlock()

	if e, found := t.entries[devTag]; found {
		prev := e.lastReg
		if e.pub == pubkey {
			e.lastReg = now
			res := Result{DevTag: devTag, Pubkey: pubkey, TunnelIP: e.ip, Action: ActionRefreshed, Idle: now.Sub(prev)}
			t.logf("peer: ~ dev=%s refresh (idle=%s) n=%d/%d", devShort(devTag), roundDur(res.Idle), len(t.entries), t.max)
			return res, nil
		}
		// 身份轮换：先移除旧 peer 再写新的 —— 顺序固定，避免旧 allowed_ip 悬空
		//（两步包进同一个后台 op，串行保序）。
		oldPub, oldIP := e.pub, e.ip
		// 接收路径：只入队不等完成（FIX-67；顺序由单消费者队列保证）。
		t.applyDeviceOpAsync(func() {
			if rerr := t.cfg.RemovePeer(oldPub); rerr != nil {
				t.logf("peer: ! dev=%s rotate 移除旧 peer（pub=%s）失败：%v", devShort(devTag), pubShort(oldPub), rerr)
			}
		}, "rotate-remove")
		ip, aerr := t.assignIPLocked(secret, pubkey, devTag)
		if aerr != nil {
			return Result{}, aerr
		}
		tunIP, aerr := t.assignTunIPLocked(secret, pubkey, devTag)
		if aerr != nil {
			return Result{}, aerr
		}
		e.pub, e.psk, e.ip, e.tunIP, e.lastReg = pubkey, psk, ip, tunIP, now
		t.applyDeviceOpAsync(func() {
			if aerr := t.cfg.AddPeer(PeerConfig{Pubkey: pubkey, PSK: psk, TunnelIP: ip, TunIP: tunIP}); aerr != nil {
				t.logf("peer: ! dev=%s rotate 写入新 peer（pub=%s）失败：%v", devShort(devTag), pubShort(pubkey), aerr)
			}
		}, "rotate-add")
		res := Result{DevTag: devTag, Pubkey: pubkey, TunnelIP: ip, Action: ActionRotated,
			OldPubkey: oldPub, OldIP: oldIP, Idle: now.Sub(prev)}
		t.logf("peer: ~ dev=%s rotate pub=%s→%s ip=%v→%v n=%d/%d",
			devShort(devTag), pubShort(oldPub), pubShort(pubkey), oldIP, ip, len(t.entries), t.max)
		return res, nil
	}

	if len(t.entries) >= t.max {
		if !t.evictStaleLocked(now) {
			t.noteReject(RejTableFull, "peer: ! dev=%s reject reason=table-full n=%d/%d", devShort(devTag), len(t.entries), t.max)
			return Result{}, ErrTableFull
		}
	}
	ip, aerr := t.assignIPLocked(secret, pubkey, devTag)
	if aerr != nil {
		return Result{}, aerr
	}
	tunIP, aerr := t.assignTunIPLocked(secret, pubkey, devTag)
	if aerr != nil {
		return Result{}, aerr
	}
	e := &dentry{dev: devTag, pub: pubkey, psk: psk, ip: ip, tunIP: tunIP, lastReg: now, createdAt: now}
	t.entries[devTag] = e
	t.applyDeviceOpAsync(func() {
		if aerr := t.cfg.AddPeer(PeerConfig{Pubkey: pubkey, PSK: psk, TunnelIP: ip, TunIP: tunIP}); aerr != nil {
			t.logf("peer: ! dev=%s 写入 peer（pub=%s）失败：%v", devShort(devTag), pubShort(pubkey), aerr)
		}
	}, "add")
	if other, ok := t.findByPubLocked(pubkey, devTag); ok {
		t.logf("peer: ! pub=%s 同时登记在 dev=%s 与 dev=%s（疑似同一身份被两台设备使用：克隆/迁移过应用数据？）",
			pubShort(pubkey), devShort(other), devShort(devTag))
	}
	t.logf("peer: + dev=%s pub=%s ip=%v n=%d/%d", devShort(devTag), pubShort(pubkey), ip, len(t.entries), t.max)
	return Result{DevTag: devTag, Pubkey: pubkey, TunnelIP: ip, Action: ActionAdded}, nil
}

// GC 回收超过 TTL 未刷新的设备，返回被回收的条目（每个都打了日志）。
func (t *DeviceTable) GC(now time.Time) []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ttl <= 0 {
		return nil
	}
	var victims []*dentry
	for _, e := range t.entries {
		if now.Sub(e.lastReg) > t.ttl {
			victims = append(victims, e)
		}
	}
	out := make([]Result, 0, len(victims))
	for _, e := range victims {
		res := Result{DevTag: e.dev, Pubkey: e.pub, TunnelIP: e.ip, Action: ActionExpired, Idle: now.Sub(e.lastReg)}
		t.removeLocked(e)
		t.logf("peer: - dev=%s reason=ttl (idle=%s) n=%d/%d", devShort(res.DevTag), roundDur(res.Idle), len(t.entries), t.max)
		out = append(out, res)
	}
	return out
}

// RunGC 周期回收（ctx 结束即退出）。every<=0 或 TTL 关闭时不做事。
// 节拍带 ±10% 抖动：多出口同时扫表时错开。
func (t *DeviceTable) RunGC(ctx context.Context, every time.Duration) {
	if every <= 0 || t.ttl <= 0 {
		return
	}
	for {
		wait := time.Duration(float64(every) * (0.9 + 0.2*rand.Float64()))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		t.GC(time.Now())
	}
}

// evictStaleLocked 表满时淘汰：只在「超过 grace 未刷新」的设备里挑最旧的一条。
// 返回 false = 全部活跃（调用方应拒绝新设备，绝不淘汰在线设备）。
func (t *DeviceTable) evictStaleLocked(now time.Time) bool {
	var victim *dentry
	for _, e := range t.entries {
		if now.Sub(e.lastReg) <= t.grace {
			continue // 活跃宽限期内：不碰
		}
		if victim == nil || e.lastReg.Before(victim.lastReg) {
			victim = e
		}
	}
	if victim == nil {
		return false
	}
	idle := now.Sub(victim.lastReg)
	dev := victim.dev
	t.removeLocked(victim)
	t.logf("peer: - dev=%s reason=stale (idle=%s) n=%d/%d", devShort(dev), roundDur(idle), len(t.entries), t.max)
	return true
}

// assignIPLocked：隧道地址 = 两端各自从 (secret, 公钥) 派生（tasks 3.7）。
// 理论冲突（cap=32 时 ≈0.05%）退到池分配并大声告警 —— 注意身份持久化之后
// 重启不再换钥匙，消解冲突要靠用户「重置本机身份」。
func (t *DeviceTable) assignIPLocked(secret [32]byte, pub [32]byte, dev proto.DevTag) (netip.Addr, error) {
	ip := proto.DeriveTunnelIP(secret, pub)
	if !t.ipTakenLocked(ip) {
		return ip, nil
	}
	// 同公钥不同 devTag（克隆/迁移应用数据的既有场景）：同一把钥匙派生地址本就相同，
	// 不算冲突——沿用该地址（上层会打「疑似同一身份」告警）；设备实际用的就是这个地址，
	// 记录也不「注定不通」。
	if t.ipHeldByPubLocked(pub, ip) {
		return ip, nil
	}
	t.noteReject(RejConflict, "peer: ! dev=%s reject reason=ip-conflict ip=%v（派生地址与在表设备撞车；消解 = 手机上「重置本机身份」后重连）",
		devShort(dev), ip)
	return netip.Addr{}, ErrTunnelIPConflict
}

// ipHeldByPubLocked 该地址是否由**同一公钥**的条目持有（克隆场景的判据）。
func (t *DeviceTable) ipHeldByPubLocked(pub [32]byte, ip netip.Addr) bool {
	for _, e := range t.entries {
		if e.pub == pub && (e.ip == ip || e.tunIP == ip) {
			return true
		}
	}
	return false
}

// ipTakenLocked 判断某地址是否已被表内设备占用（调用方持锁）。**双地址集合**
// （review #16）：隧道地址与应用面地址共用一个 /16 空间，任一类的冲突都让
// allowedips 的 /32 撞车——必须并集判定。
func (t *DeviceTable) ipTakenLocked(ip netip.Addr) bool {
	for _, e := range t.entries {
		if e.ip == ip || e.tunIP == ip {
			return true
		}
	}
	return false
}

// assignTunIPLocked：应用面地址 = proto.DeriveTunIP（同设备相等已在 proto 层守卫）；
// 与**其他设备**的任一地址撞车时退池并大声告警（与隧道地址冲突同语义：客户端仍用
// 派生地址 ⇒ 该设备应用面不通，消解靠手机「重置本机身份」）。
func (t *DeviceTable) assignTunIPLocked(secret [32]byte, pub [32]byte, dev proto.DevTag) (netip.Addr, error) {
	ip := proto.DeriveTunIP(secret, pub)
	if !t.ipTakenLocked(ip) {
		return ip, nil
	}
	if t.ipHeldByPubLocked(pub, ip) { // 同公钥（克隆）：同址合法，见 assignIPLocked
		return ip, nil
	}
	t.noteReject(RejConflict, "peer: ! dev=%s reject reason=ip-conflict tunip=%v（应用面派生地址与在表设备撞车）", devShort(dev), ip)
	return netip.Addr{}, ErrTunnelIPConflict
}

// findByPubLocked 找「同一公钥挂在别的 devTag 上」的条目（克隆检测，诊断用）。
func (t *DeviceTable) findByPubLocked(pub [32]byte, except proto.DevTag) (proto.DevTag, bool) {
	for dev, e := range t.entries {
		if dev != except && e.pub == pub {
			return dev, true
		}
	}
	return proto.DevTag{}, false
}

func (t *DeviceTable) removeLocked(e *dentry) {
	delete(t.entries, e.dev) // map 删除带显式 found 语义（下面 Release 幂等）
	pub := e.pub
	t.applyDeviceOp(func() {
		if err := t.cfg.RemovePeer(pub); err != nil {
			t.logf("peer: ! dev=%s 移除 peer（pub=%s）失败：%v", devShort(e.dev), pubShort(pub), err)
		}
	})
}

// Len 当前设备数。
func (t *DeviceTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// DeviceBrief 设备表快照条目（serve.status 的 peer 表数据源，role-management 2.1/D10）。
type DeviceBrief struct {
	Dev      string // devTag 短指纹（hex 前 8 字节）
	TunnelIP string // 隧道侧 /32
	LastReg  time.Time
	Idle     time.Duration // 距最近一次成功注册
}

// Briefs 设备表快照（serve 角色状态面；锁内拷贝）。
func (t *DeviceTable) Briefs() []DeviceBrief {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]DeviceBrief, 0, len(t.entries))
	now := time.Now()
	for _, e := range t.entries {
		out = append(out, DeviceBrief{
			Dev:      hex.EncodeToString(e.dev[:8]),
			TunnelIP: e.ip.String(),
			LastReg:  e.lastReg,
			Idle:     now.Sub(e.lastReg),
		})
	}
	return out
}

// Cap 容量。
func (t *DeviceTable) Cap() int { return t.max }

// Limits 返回 (cap, ttl, grace)，启动日志用。
func (t *DeviceTable) Limits() (int, time.Duration, time.Duration) { return t.max, t.ttl, t.grace }

// TunnelIP 查询某公钥的隧道地址（诊断）。found 显式返回——netip 零值不是哨兵。
func (t *DeviceTable) TunnelIP(pub [32]byte) (netip.Addr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.entries {
		if e.pub == pub {
			return e.ip, true
		}
	}
	return netip.Addr{}, false
}

// devShort / pubShort：日志用短指纹（4 字节 hex）。
func devShort(d proto.DevTag) string { return hex.EncodeToString(d[:4]) }
func pubShort(p [32]byte) string     { return hex.EncodeToString(p[:4]) }

func roundDur(d time.Duration) time.Duration { return d.Round(time.Second) }
