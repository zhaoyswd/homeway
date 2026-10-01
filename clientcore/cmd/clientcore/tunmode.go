//go:build cshared

// App 专用：tier-core 客户端核（CLI 不编）
// tunmode.go — tier-core（本移植私有扩展，上游 tailcat 无此功能）：
// VPN 扩展的 TUN fd → gVisor netstack（gVisor，已随 tailcat 数据面链接）
// → 每条流经 tailcat Client（exit-node 客户端语义）拨出到出口节点。
// TCP/UDP 全量代理；ICMP 不代理（v1，ping 到隧道外目标不通）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// tunConfig 已随迁 hostsession.Config（host-registry-daemon D1：本文件经
// hostsession_shell.go 的类型别名 + normalizeTunConfig 薄壳引用，下方引用点零改动）。

// tunStats 逐项计数：与设备 /proc/net/dev 的 vpn-tun 行对表，用来确认
// 「fd 读=应用上行 / fd 写=回程」的方向约定，并暴露静默丢弃。
type tunStats struct {
	// l3-exit-intercept 后手机侧只剩这四个有写入方的计数（review 复审 #1 收尾：
	// 拆掉了 gVisor/旧流模型遗留的十几个恒 0 字段，判据行不冒充统计）。
	fdReadBytes  atomic.Int64 // 应用 TUN 读字节（上行）
	fdWriteBytes atomic.Int64 // 应用 TUN 写字节（下行）
	// 并发流保险阀（S22）：端口转发与桥共用，防失控应用把 goroutine/内存打满。
	tcpFlows     atomic.Int64
	flowRejected atomic.Int64
	// 端口转发计数（app_portfwd.go；由 tunStatusJSON 的 stats 块下发）。
	pfAccepted atomic.Int64
	pfFails    atomic.Int64
}

func (s *tunStats) String() string {
	// l3-exit-intercept：每流 TCP/UDP 统计移至出口日志（intercept: 行）；DNS 计数随
	// 手机侧解析逻辑整体移除（dns-host-resolver），口径在出口代答的 `dns: q=…` 行。
	return fmt.Sprintf(
		"fdReadBytes=%dB fdWriteBytes=%dB | pf=%d/%d",
		s.fdReadBytes.Load(), s.fdWriteBytes.Load(),
		s.pfAccepted.Load(), s.pfFails.Load())
}

// tunRun 代表「一次 tun 核心运行」（一个世代）。
// 单飞锁（probeRunning）与健康位（tunHealthy）都是包级共享的，而旧世代的 goroutine
// 往往要到新世代起来之后才真正退出（TUN fd 被系统收回 → 读报错 → 函数返回）。
// 旧世代退出时若无条件清这两个共享状态，就会把新世代一起关掉：现象是核心刚连上一秒
// 就被判「核心退出」→ 重建 → 又立刻退出 → 无限重连。
// 规则：**只有当前世代才有权改这两个共享状态**。
type tunRun struct {
	stop     chan struct{} // 由 tunStopWait 关闭：请求本世代收工
	stopOnce sync.Once
	done     chan struct{} // 本世代真正退出时关闭

	// attachCh 两阶段启动用：扩展在 prepare 就绪后把 TUN fd 递进来（缓冲 1，只接受一次）。
	attachCh chan int

	// endpointCacheDir 端点学习缓存目录（新栈：三层来源缓存；空 = 不学）。
	endpointCacheDir string

	// cl 本世代的出口会话（wgcore.Transport）。换网/挂起唤醒时扩展经 ClientCoreTunRecover
	// 下推恢复阶梯（recover.go），就地重握手/换源/重赛跑，不必拆掉整条隧道重建。
	// tr 本世代的 runner：tunStatusJSON 读它的统计/链路快照；stop 路径打斷暖机。
	// clClosed 记录"客户端已被关闭"这件事（**不能用 sync.Once 表达**，理由见 closeClientOnce）。
	// recoverGate 本世代的恢复闸（评审 P1-1：按世代隔离，旧世代的陈旧轮不挡新世代）。
	clMu        sync.Mutex
	cl          exitSession // 本世代出口会话（= newSession，见 session.go）
	clClosed    bool
	tr          *tunRunner
	recoverGate recoverGate
}

func (r *tunRun) setRunner(tr *tunRunner) {
	r.clMu.Lock()
	r.tr = tr
	r.clMu.Unlock()
}

func (r *tunRun) runner() *tunRunner {
	r.clMu.Lock()
	defer r.clMu.Unlock()
	return r.tr
}

// setClient 记录本世代的客户端。
// 若收工已经发生在它之前（暖机期被 stop：`tunStopWait` 先调了 closeClientOnce，
// 那时 cl 还是 nil），就地把它关掉 —— 否则这个客户端会一直挂着，出口侧留一个半开 peer。
func (r *tunRun) setClient(cl exitSession) {
	r.clMu.Lock()
	r.cl = cl
	closed := r.clClosed
	r.clMu.Unlock()
	if closed {
		_ = cl.Close()
	}
}

func (r *tunRun) client() exitSession {
	r.clMu.Lock()
	defer r.clMu.Unlock()
	return r.cl
}

var (
	tunMu  sync.Mutex
	tunNow *tunRun
)

// 链路巡检固定 60s：探测的存在意义是保活（NAT 映射 / 对端路径信任）与可达性判定
// （连续 3 次无响应 → 不健康 → 自愈重建）——都是写给隧道的，不该被 UI 消费驱动。
// 界面新鲜度与探测节拍解耦：扩展前台时每 5s 读一次状态快照（路径/延迟是上次探测的
// 结果，流量是实时计数），纯读、不触发新探测；App 回到前台时经 ClientCoreTunSetForeground
// 踢一次立即探测，让链路数据在用户注视恢复的 1–2s 内新鲜（连接完成时另有一次立即探测）。
const patrolInterval = 60 * time.Second

// relayUpgradeEvery：停留中继时，每多少拍巡检做一次"重新武装赛跑试直连"（5 拍 = 5 分钟）。
// 为什么需要：路径选定后是单路径发送 —— 中继先回、直连其实也可达时会一直走中继；
// 出口的盲打只在 hint 那几次发生，丢了就没人再"把直连的包送上门"。
const relayUpgradeEvery = 5

// relayUpgradeStreak：连续停留中继的拍数（一旦不是中继就清零）。纯函数，单测覆盖。
func relayUpgradeStreak(via string, streak int) int {
	if via == "relay" {
		return streak + 1
	}
	return 0
}

// relayUpgradeDue：该不该做这一轮升级尝试。纯函数，单测覆盖。
func relayUpgradeDue(via string, streak int) bool {
	return via == "relay" && streak >= relayUpgradeEvery
}

// 巡检连败时间窗（10 分钟）：真源 = hostsession.servicePatrolFailWindow（FIX-20
// 收口——本包 gate 副本已删，手机门直接调 hostsession.PatrolEvidenceGate，窗口
// 常量随函数单一化；2026-09-23 事故形态见 hostsession 侧注释）。

var (
	// tunForeground：上次下发的"App 是否在前台"。已不影响巡检节拍（固定 60s），
	// 只用于让"回到前台"仅在状态转变时踢一次探测。
	tunForeground atomic.Bool
	// patrolKick：回前台时踢一次巡检（有界缓冲，重复触发自动合并）。
	patrolKick = make(chan struct{}, 1)
)

func init() { tunForeground.Store(true) }

// setTunForeground 由扩展经 NAPI（ClientCoreTunSetForeground）调用：回到前台时踢一次
// 巡检——固定间隔下，用户回到界面时链路快照可能已落后最多 60s，踢一下让新数据在
// 1–2s 内就位（扩展侧回前台也会立即读一次快照，两者互补）。
func setTunForeground(fg bool) {
	was := tunForeground.Swap(fg)
	if fg && !was {
		select {
		case patrolKick <- struct{}{}:
		default:
		}
	}
}

// beginTunRun 开启新世代（每次 prepare/start 调用一次）。
func beginTunRun() *tunRun {
	r := &tunRun{
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		attachCh: make(chan int, 1),
	}
	tunMu.Lock()
	tunNow = r
	tunMu.Unlock()
	return r
}

func (r *tunRun) closeClientOnce() {
	r.clMu.Lock()
	cl := r.cl
	already := r.clClosed
	r.clClosed = true
	r.clMu.Unlock()
	if cl != nil && !already {
		_ = cl.Close()
	}
}

func currentTunRun() *tunRun {
	tunMu.Lock()
	defer tunMu.Unlock()
	return tunNow
}

// isCurrent 本世代是否仍是当前世代（旧世代不得再改共享状态）。
func (r *tunRun) isCurrent() bool {
	if r == nil {
		return false
	}
	return currentTunRun() == r
}

// setStageIfCurrent 只有**当前世代**才有权改阶段与原因。
//
// 为什么必须这么写（2026-09-14 修）：`tunStopWait` 3s 超时后会强制放锁，让扩展立刻起新世代；
// 而旧世代的 goroutine 往往还卡在 `ci.Expand`（地图拉取上限 12s）里，等它醒来时新世代已经在
// 暖机 —— 它若照旧写 `stageFailed`/`stageIdle`，就把**正在暖机的新世代**改写成失败/空闲，
// 扩展据此判死并重连（表现为"莫名其妙的重连循环"）。单飞锁有世代守卫，stage 也必须一起有。
func (r *tunRun) setStageIfCurrent(s tunStage, code, reason string, meowed bool) {
	if !r.isCurrent() {
		return
	}
	setStage(s, code, reason, meowed)
}

// markUnhealthy fd 循环出错：只有当前世代才有权标记不健康。
// reason（demand-driven-recovery D3 的分类，进状态 JSON 的 unhealthyReason——
// 扩展据此选文案与门控：patrol=传输类（受需求门控），fd/panic/stop=设备层/核内部
// （不门控，立即可见））：
//   - "patrol"：巡检 3 连败后阶梯仍失败（传输死亡）——唯一受需求门控的类；
//   - "fd"：TUN fd 读写错误（接口被系统收回等，用户流量已在黑洞）；
//   - "panic"：巡检 goroutine panic 兜底（核内部错误）；
//   - "stop"：收工超时强制放锁。
func (r *tunRun) markUnhealthy(reason string) {
	if r.isCurrent() {
		// 写序契约：先 reason 后 healthy——读方先见 healthy=false 时 reason 必已就位
		//（评审 M3；两个原子值合成一个是更彻底的做法，窄窗口的后果仅文案短暂不准）。
		tunUnhealthyWhy.Store(reason)
		tunHealthy.Store(false)
	}
}

// finish 本世代退出：关掉 done 并释放单飞锁；旧世代退出不得影响新世代。
// stop 一并关（评审 3-3）：世代自行退出（fd 错误/收工超时）时 tunStopWait 不会跑，
// 不关 stop 会让下推器/巡检/统计 goroutine 每秒空转到进程结束；与 tunStopWait 共用
// stopOnce，幂等。
func (r *tunRun) finish() {
	r.stopOnce.Do(func() { close(r.stop) })
	close(r.done)
	if r.isCurrent() {
		tunUnhealthyWhy.Store("stop") // 评审 M3：世代退出也是不健康的一类（reason 四类闭合）
		tunHealthy.Store(false)
		probeRunning.Store(0)
	}
}

// markUnhealthy fd 循环出错时标记隧道不健康；只有当前世代才有权改这个共享状态
// （旧世代的 fd 早已被系统收回，报错是必然的，不能拿它判新世代死没死）。
// reason 语义见 tunRun.markUnhealthy。
func (t *tunRunner) markUnhealthy(reason string) { t.run.markUnhealthy(reason) }

// refreshFdStats 把 attach 面（hub）的实时 fd 计数拷进本世代 stats。
// 状态 JSON 的 stats 段被读时现刷（界面/通知的消费节拍 ~5s），周期统计 ticker 打
// `stats:` 日志行前也刷同一份。原先只有 ticker 在拷（StatsSecs 默认 60）——那是
// 日志行的节拍，却成了界面流量的刷新率：连接后头一分钟恒 0、之后 60s 一格跳变
// （2026-09-25 真机 FMR：内核 vpn-tun 已 448B，界面仍 ↑0 B ↓0 B）。
func (t *tunRunner) refreshFdStats() {
	if a, ok := tunAttachSurfaceOf(t.cl); ok {
		rb, wb := a.FdStats()
		t.st.fdReadBytes.Store(rb)
		t.st.fdWriteBytes.Store(wb)
	}
}

type tunRunner struct {
	run  *tunRun
	logf Logf
	cl   exitSession
	// bridge 回环桥宿主（app_bridge.go）：attached 时起、世代收工时停。
	// files/term 消费方连 127.0.0.1:7722/7723，与本结构解耦（服务会话可作另一宿主）。
	bridge *bridgeHost
	// 注意：**不持有** TUN fd 的 *os.File —— fd 归扩展（系统框架）所有，核只读写裸 fd
	//（见 attach 处的注释与 AGENTS 坑 50）。
	st          tunStats
	dialTimeout time.Duration

	// 最近一次链路巡检的结果 + 时间戳：由 tunStatusJSON 下发给扩展（界面不再靠正则解析日志）。
	linkMu    sync.Mutex
	linkVia   string // direct | relay
	linkEP    string // direct 时的对端端点
	linkRttMs int64
	linkAt    int64 // unix **毫秒**（0 = 还没探过；review #33：与 wtransport.Status 的
	// AdoptedAt/At（UnixMilli）统一——此前这里写秒、那边写毫秒，扩展侧要靠
	// 数值量级猜单位归一，混用即误判「不新鲜」）

	// 端口转发（app_portfwd.go）：本世代的监听器与每条映射的状态。
	pfMu     sync.Mutex
	pfStates []*pfState
	pfLn     []net.Listener
}

// setLink 记录一次巡检结果（见 link* 字段）。
func (t *tunRunner) setLink(via, ep string, rttMs int64) {
	t.linkMu.Lock()
	t.linkVia, t.linkEP, t.linkRttMs, t.linkAt = via, ep, rttMs, time.Now().UnixMilli()
	t.linkMu.Unlock()
}

// linkSnapshot 读一份链路快照给状态 JSON 用。
func (t *tunRunner) linkSnapshot() (via, ep string, rttMs, at int64) {
	t.linkMu.Lock()
	defer t.linkMu.Unlock()
	return t.linkVia, t.linkEP, t.linkRttMs, t.linkAt
}

// TUN 设备 ioctl（arm64 Linux / OHOS 内核同 ABI）
const (
	tunGetIff = 0x802854d2 // _IOR('T', 210, struct ifreq)
	iffTun    = 0x0001
	iffTap    = 0x0002
	iffNoPI   = 0x1000
)

type ifreqFlags struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// logFdInfo 打印 TUN fd 的真实属性：是不是字符设备、内核给的接口名与
// IFF_TUN/IFF_NO_PI 标志。这是「写侧要不要 packet-info」的唯一权威答案。
func logFdInfo(logf Logf, fd int) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		logf("tun fd=%d fstat: %v", fd, err)
	} else {
		logf("tun fd=%d mode=%#o isCharDev=%v", fd, st.Mode, st.Mode&unix.S_IFMT == unix.S_IFCHR)
	}
	var ifr ifreqFlags
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), tunGetIff, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		logf("tun fd=%d TUNGETIFF: %v", fd, errno)
		return
	}
	name := string(bytes.TrimRight(ifr.name[:], "\x00"))
	logf("tun fd=%d TUNGETIFF name=%q flags=%#04x (IFF_TUN=%v IFF_TAP=%v IFF_NO_PI=%v)",
		fd, name, ifr.flags, ifr.flags&iffTun != 0, ifr.flags&iffTap != 0, ifr.flags&iffNoPI != 0)
}

// fdSnapshot 汇总本进程 fd 的构成（文件 / socket / anon_inode 分类 + socket 家族细分）。
// 排查「too many open files」用：先看清是谁在涨，只看总数会被 fd 类型混淆。
// 曾经还带一段「/proc/self/net 各协议表行数」——2026-09-25 真机探针实测扩展进程读
// /proc/net/* 一律 EACCES（SELinux），该段在设备上恒为 "?"，已删。
func fdSnapshot() string {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return "read /proc/self/fd: " + err.Error()
	}
	var nSocket, nFile, nAnon, nOther int
	dirs := map[string]int{}
	fams := map[string]int{}
	for _, e := range ents {
		target, rerr := os.Readlink("/proc/self/fd/" + e.Name())
		if rerr != nil {
			nOther++
			continue
		}
		switch {
		case strings.HasPrefix(target, "socket:["):
			nSocket++
			fd, ferr := strconv.Atoi(e.Name())
			if ferr == nil {
				fams[sockDesc(fd)]++
			}
		case strings.HasPrefix(target, "anon_inode:"):
			nAnon++
		case strings.HasPrefix(target, "/"):
			nFile++
			dirs[path.Dir(target)]++
		default:
			nOther++
		}
	}
	// 各协议表的数据行数（首行是表头）：本进程所在 netns 的视角。
	type kv struct {
		k string
		n int
	}
	var top []kv
	for k, n := range dirs {
		top = append(top, kv{k, n})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
	topStr := ""
	for i, it := range top {
		if i >= 3 {
			break
		}
		topStr += fmt.Sprintf(" %s=%d", it.k, it.n)
	}
	var famKeys []kv
	for k, n := range fams {
		famKeys = append(famKeys, kv{k, n})
	}
	sort.Slice(famKeys, func(i, j int) bool { return famKeys[i].n > famKeys[j].n })
	famStr := ""
	for i, it := range famKeys {
		if i >= 6 {
			break
		}
		famStr += fmt.Sprintf(" %s=%d", it.k, it.n)
	}
	return fmt.Sprintf("total=%d socket=%d file=%d anon=%d other=%d goroutine=%d | fam:%s |%s",
		len(ents), nSocket, nFile, nAnon, nOther, runtime.NumGoroutine(), famStr, topStr)
}

// sockDesc 用 SO_DOMAIN/SO_TYPE 给一个 socket fd 分类（读不到就返回 "?"）。
// 这是把「5 个/秒的泄漏」定位到具体家族的唯一可靠办法：fd 列表里只有
// `socket:[inode]` 看不出是 AF_INET 还是 AF_NETLINK。
func sockDesc(fd int) string {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, soDomain)
	if err != nil {
		return "?"
	}
	typ, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	d := map[int]string{
		unix.AF_INET: "inet", unix.AF_INET6: "inet6", unix.AF_UNIX: "unix",
		afNetlink: "netlink", afPacket: "packet",
	}[domain]
	if d == "" {
		d = fmt.Sprintf("af%d", domain)
	}
	t := map[int]string{
		unix.SOCK_STREAM: "tcp", unix.SOCK_DGRAM: "udp", unix.SOCK_RAW: "raw",
	}[typ]
	if t == "" {
		t = fmt.Sprintf("t%d", typ)
	}
	out := d + "/" + t
	if la, lerr := unix.Getsockname(fd); lerr == nil {
		out += "@" + sockAddrString(la)
	}
	if pa, perr := unix.Getpeername(fd); perr == nil {
		if s := sockAddrString(pa); s != "0.0.0.0:0" && s != "[::]:0" {
			out += "->" + s
		}
	}
	return out
}

// sockAddrString 把 Sockaddr 转成 "ip:port"（只处理 v4/v6，其它返回 "?"）。
func sockAddrString(sa unix.Sockaddr) string {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(a.Addr).String() + ":" + strconv.Itoa(a.Port)
	case *unix.SockaddrInet6:
		return "[" + netip.AddrFrom16(a.Addr).String() + "]:" + strconv.Itoa(a.Port)
	default:
		return "?"
	}
}

// ---------------------------------------------------------------- 两阶段启动
//
// 见 openspec/changes/tun-prepare-attach-split：
//   prepare —— 暖机与出口注册，**不依赖 TUN fd**（token 解析/设备身份/WG 握手/暖机探测）；
//   attach  —— 把 fd 接进 netstack 并开始转发。
// 好处：状态栏标记（= VPN 接口建起来）与"隧道可用"落在同一时刻，不再有"接口在、隧道不通"
// 的黑洞窗口；硬失败也能在接口建起来之前干净收场（不建接口 ⇒ 无需回滚、标记不残留）。
//
// 生命周期约束（design 决策 5，逐条对应下面实现）：
//   - 单飞锁在 prepare 取、由**整个世代的收工**释放（不再对应某一次调用）；
//   - prepare 成功后 attachDeadline 内没有 attach ⇒ 自行收工放锁（attach-timeout）；
//   - attach 失败 ⇒ 整体收工，不放回 ready（不留"已暖机未接管"的中间态）；
//   - stop 在 preparing 阶段靠**关闭客户端**打断暖机（卡住的是拉地图/起引擎，不是 Ping）；
//   - 旧世代不得改阶段/原因（沿用 isCurrent 守卫）。

// 并发流上限（保险阀，见 tunStats.tcpFlows）。取值远高于正常使用量：
// 目的是防"失控应用把内存/goroutine 打满"，不是做流量整形。
const maxTCPFlows = 4096

type tunStage int32

const (
	stageIdle tunStage = iota
	stagePreparing
	stageReady    // 暖机完成，等待 attach
	stageAttached // 已接管数据面
	stageFailed
)

var (
	stageMu      sync.Mutex
	stageReadyBy string // 最近一次就绪的判据（现仅 "wg"：隧道内暖机探测；随 tunStatusJSON 下发）
	stageNow     = stageIdle
	stageCode    string // 机器可读原因码：core / attach / stopped / attach-timeout（空=正常）
	stageReason  string // 给人看的原因（可含错误原文）
	stageMeowed  bool
	stageSince   = time.Now()
)

func tunStageName(s tunStage) string {
	switch s {
	case stagePreparing:
		return "preparing"
	case stageReady:
		return "ready"
	case stageAttached:
		return "attached"
	case stageFailed:
		return "failed"
	default:
		return "idle"
	}
}

// setStage 进入某阶段。code 是机器可读的原因码（扩展据此把失败映射成界面文案：
// core→会话/核类、attach→数据面类、stopped/attach-timeout→中止）。
// meowed=false 且阶段为 ready 时表示软失败（暖机窗口内没等到注册确认）。
// setReadyBy 记录最近一次就绪的判据（现仅 "wg"），随 tunStatusJSON 下发。
func setReadyBy(by string) {
	stageMu.Lock()
	stageReadyBy = by
	stageMu.Unlock()
}

func setStage(s tunStage, code, reason string, meowed bool) {
	stageMu.Lock()
	stageNow, stageCode, stageReason, stageMeowed, stageSince = s, code, reason, meowed, time.Now()
	stageMu.Unlock()
}

func tunStageSnapshot() (tunStage, string, string, bool) {
	stageMu.Lock()
	defer stageMu.Unlock()
	return stageNow, stageCode, stageReason, stageMeowed
}

// tunRunningValue 是 ClientCoreTunRunning 的唯一实现：**只有接上数据面且健康**才算 1。
// 语义比原先收紧（原先只看单飞锁）：prepare 阶段锁已经持有，但那时隧道还不能承载流量。
func tunRunningValue() int {
	// 注意：这三个信号（单飞锁/健康位/阶段）各自原子、**合起来不是一致快照** ⇒ 转换瞬间可能
	// 瞬时返回 0/1。调用方（扩展的自愈巡检）已用 everConnected + 连续失败预算去抖，
	// 这里不再加锁 —— 加锁会把热路径上每次状态查询都变成争锁。
	if probeRunning.Load() == 0 || !tunHealthy.Load() {
		return 0
	}
	if st, _, _, _ := tunStageSnapshot(); st != stageAttached {
		return 0
	}
	return 1
}

// tunStatusJSON 供扩展查询（替代"读日志找 running"，也让失败归因能写准）。
// 字段与 tailcat/src/main/cpp/types/libtailcat/Index.d.ts 的说明保持一致。
//
// **stats / link 是 2026-09-14 新增的结构化通道**：原先扩展用正则去解析核日志的 `stats:` 行与
// `link: via=…` 行来驱动界面的链路条/流量/软失败判定 —— 核里改一句日志措辞就静默坏掉（无编译
// 错、无测试红）。现在这些值直接作为 JSON 字段下发，日志只留作排查用途。
func tunStatusJSON() string {
	st, code, reason, meowed := tunStageSnapshot()
	stageMu.Lock()
	since := stageSince
	stageMu.Unlock()
	elapsed := int64(0)
	if !since.IsZero() {
		elapsed = time.Since(since).Milliseconds()
	}
	stageMu.Lock()
	rby := stageReadyBy
	stageMu.Unlock()
	m := map[string]any{
		"state":     tunStageName(st),
		"code":      code,
		"reason":    reason,
		"meowed":    meowed,
		"readyBy":   rby,
		"elapsedMs": elapsed,
		"running":   tunRunningValue(),
	}
	// demand-driven-recovery：需求判定快照（最近一拍）与不健康原因分类——扩展的
	// 终态门控（传输类+无需求 ⇒ 不写 failed）与诊断报告同源消费。
	dm := demandSnapshotJSON()
	if r := currentTunRun(); r != nil {
		if tr := r.runner(); tr != nil {
			if tp := newTransport(tr.cl); tp != nil {
				if at := tp.LastTunOutboundAt(); !at.IsZero() {
					dm["outboundAt"] = at.UnixMilli() // 最近出站包时刻（评审 M7）
				}
				dm["localErrAdopted"] = tp.AdoptedLocalErrCount()
				dm["localErrTotal"] = tp.LocalSendErrCount()
			}
		}
	}
	m["demand"] = dm
	if why, _ := tunUnhealthyWhy.Load().(string); why != "" {
		m["unhealthyReason"] = why
	}
	if r := currentTunRun(); r != nil {
		if tr := r.runner(); tr != nil {
			tr.refreshFdStats() // fd 计数现读现给，不吃统计 ticker 的旧值
			m["stats"] = map[string]any{
				// l3-exit-intercept：每流 TCP/UDP 统计移至出口日志；手机侧保留
				// fd 字节与端口转发计数（诊断报告与流量显示的消费面；DNS 口径在出口代答）。
				"fdReadBytes":  tr.st.fdReadBytes.Load(),
				"fdWriteBytes": tr.st.fdWriteBytes.Load(),
				"pfAccepted":   tr.st.pfAccepted.Load(),
				"pfFails":      tr.st.pfFails.Load(),
			}
			via, ep, rttMs, at := tr.linkSnapshot()
			// dns-host-resolver：出口隧道 IP（扩展用它作 VpnConfig 的 dnsAddresses；
			// 查询经隧道命中出口 :53 改写 → 本机代答）。常量契约见 wgcore DefaultTunnelIP。
			m["exitIp"] = tr.cl.ServerTunnelIP().String()
			m["link"] = map[string]any{
				"via":   via,
				"ep":    ep,
				"rttMs": rttMs,
				"at":    at,
			}
			m["portForwards"] = tr.pfStatusJSON()
			// 回环桥鉴权 blob（hex(魔数+令牌)）与 socket 路径（app-bridge-uds）：
			// 只经状态通道分发给自家 App，不进日志/诊断报告。桥未起时为空串。
			if tr.bridge != nil {
				m["bridgeAuth"] = tr.bridge.authHex()
				fs, ts, ss := tr.bridge.sockJSON()
				m["bridgeFilesSock"], m["bridgeTermSock"], m["bridgeSpeedSock"] = fs, ts, ss
			}
		}
		// 最近一次直连探针尝试的结构化摘要（openspec direct-ready-faststart
		// 任务 0.2：归因「握手未完成 / 握手成但往返不回」；空 = 本世代还没探过）。
	}
	// 设备身份短指纹（只公钥/devTag，私钥不外出）：App 诊断报告与出口日志的 `peer:` 行对齐用。
	if r := currentTunRun(); r != nil {
		if cl := r.client(); cl != nil {
			if tp := newTransport(cl); tp != nil {
				if id := tp.Identity(); id != nil {
					m["identity"] = map[string]any{"dev": id.ShortDev(), "pub": id.ShortPub()}
				}
				// 应用面（VpnConfig/TUN）地址：l3-exit-intercept D4 的第二派生地址，
				// 扩展在 prepare 就绪后读它建 VPN 接口（单一来源，不与隧道 IP 混用）。
				if tp.Core() != nil {
					if ip := tp.Core().TunIP(); ip.IsValid() {
						m["tunIp"] = ip.String()
					}
				}
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return `{"state":"unknown"}`
	}
	return string(b)
}

// 阶段时长常量（design 的 Open Questions：取值可按真机数据微调，不改契约形状）。
const (
	// warmTimeout 暖机窗口：等 meowed 为止。超时算**软失败**——Dial 每次新流都会重试注册，
	// 直连打洞也可能后到，此时判死会把能自愈的会话判死（今天是"6 秒没报错就往下走"，同理）。
	warmTimeout = 20 * time.Second
	// attachDeadline prepare 成功后等 attach 的上限。唯一合法的长间隔是系统侧建接口/授权
	// （正常 1s 内完成），调用方主动放弃时应该自己 stop；这个期限只是防止锁被无人推进的世代占住。
	attachDeadline = 60 * time.Second
)

// normalizeTunConfig 已随迁 hostsession.Normalize（薄壳在 hostsession_shell.go）。

// runTun2Tailcat 一个世代的完整生命周期：暖机（prepare）→ 等 attach → 数据面 → 收工。
// 阶段状态只允许当前世代修改：收工时若已置 failed 则保留（调用方要读原因），否则回 idle。
func runTun2Tailcat(cfg tunConfig, run *tunRun) error {
	defer func() {
		if run.isCurrent() {
			if st, _, _, _ := tunStageSnapshot(); st != stageFailed {
				run.setStageIfCurrent(stageIdle, "", "", false)
			}
		}
	}()
	normalizeTunConfig(&cfg)
	// 世代起点：清掉上一轮的就绪判据。readyBy 只在暖机成功时写、不会自己过期，
	// 不清的话重建期间的状态 JSON 会一直报着旧世代的判据。
	setReadyBy("")
	if cfg.TzOffsetMinutes != 0 {
		// time.Local 是**包级全局量**：每世代都无条件重写会与所有做时间格式化的 goroutine
		//（log、http、tailcat 库）竞争（数据竞争 + 偶发错乱时间戳）。只在真的不同时才写。
		if _, cur := time.Now().In(time.Local).Zone(); cur != cfg.TzOffsetMinutes*60 {
			time.Local = time.FixedZone("device", cfg.TzOffsetMinutes*60)
		}
	}
	logf := WithPrefix(getLogf(), "tier-core: ")
	// 地址预检：解析失败是同步可判的硬失败；没内嵌中继信息时先把地图拉下来，
	// 拉不到就没必要再往下走（拿不到中继 = 注册不了 = 隧道不可能可用），
	// 而且这时**还没建 VPN 接口**，正是干净回滚的时机。
	// ---- 传输：新栈（homeway token + WG + 内部流）无条件启用（4.4 起旧栈已删）----
	cl, serr := startSession(cfg, run, logf)
	if serr != nil {
		run.setStageIfCurrent(stageFailed, "core", serr.Error(), false)
		return fmt.Errorf("新栈启动失败：%w", serr)
	}
	logf("传输：新栈（wg-native-stack）")
	run.setClient(cl) // 供 stop 打断暖机、以及 ClientCoreTunRecover 下推恢复阶梯
	// 任何退出路径（硬失败/坏 fd/attach 超时/收到停止信号）都要回收客户端：DERP/WG 连接
	// 不会因为函数返回而自己消失，漏掉就是"暖机白跑 + 出口侧留着半个 peer"。
	defer run.closeClientOnce()

	t := &tunRunner{
		run:         run,
		logf:        logf,
		cl:          cl,
		dialTimeout: time.Duration(cfg.DialMs) * time.Millisecond,
	}
	run.setRunner(t) // 供 tunStatusJSON 读 runner 的统计/链路快照

	// ---- L3 直通（l3-exit-intercept）：不再建应用侧 netstack ----
	attacher, aok := tunAttachSurfaceOf(cl)
	if !aok {
		run.setStageIfCurrent(stageFailed, "core", "传输面不支持 L3 attach", false)
		return fmt.Errorf("传输面不支持 L3 attach")
	}
	attacher.SetOnTunError(func(err error) {
		logf("tun fd 读写失败：%v（标记隧道不健康）", err)
		t.markUnhealthy("fd")
	})

	// 暖机：建好隧道（engine+DERP+disco）并完成出口注册——**不碰 TUN fd**（见文件头的两阶段说明）。
	//
	// 就绪判据是「收到 meowed」（= cl.Ping 正常返回）：出口已把本机登记为 peer，这是"能连上"的实证。
	// 但 Ping 在「客户端与出口不在同一 DERP 区域」时会**卡住不返回**（实测 >90s，ctx 到点也不返回：
	// 出口日志刷 `derp-304 does not know about peer`），所以窗口到点算**软失败**：继续准备，
	// 由 attach 后的流量触发重新注册（Dial 每次新流都会重试 up()），直连打洞也可能后到。
	// 顺带监听 run.stop：旧版这段 6 秒里是不理会停止请求的（盲区），拆开后窗口更长，必须能被打断。
	warmDone := make(chan struct{})
	var warmErr error
	warmCtx, warmCancel := context.WithTimeout(context.Background(), warmTimeout+5*time.Second)
	go func() {
		defer close(warmDone)
		// 暖机探测（就绪判据）：隧道内 TCP 拨出口必然拒绝的端口——
		// 拿到 connection refused（RST）即「会话可用」，readyBy 记为 "wg"
		// 并随状态 JSON 下发（区分「隧道真就绪」与「接口在但隧道不通」）。
		by := "wg"
		err := cl.PathProbe(warmCtx)
		if err != nil {
			warmErr = err
			logf("warmup ping: %v", err)
		} else {
			setReadyBy(by)
			logf("warmup pong: 就绪（判据=%s）", by)
		}
	}()
	meowed := false
	soft := false
	select {
	case <-warmDone:
		switch {
		case warmErr == nil:
			meowed = true
		case errors.Is(warmErr, context.DeadlineExceeded):
			soft = true // 会话建起来了，只是没等到出口确认
		default:
			// WG/端点这类失败：硬失败，此时还没建接口，干净收场
			warmCancel()
			run.setStageIfCurrent(stageFailed, "core", "建立隧道会话失败："+warmErr.Error(), false)
			return fmt.Errorf("建立隧道会话失败：%w", warmErr)
		}
	case <-run.stop:
		warmCancel()
		run.setStageIfCurrent(stageIdle, "stopped", "被停止请求中断", false)
		logf("暖机期间收到停止信号，收工（不等 attach）")
		return nil
	case <-time.After(warmTimeout):
		soft = true
	}
	warmCancel()
	if soft {
		logf("暖机 %v 内未收到 meowed：按软失败继续（attach 后由流量触发重试注册）", warmTimeout)
	}
	run.setStageIfCurrent(stageReady, "", "", meowed)
	// running 行打**真实派生地址**（review #27/#12）：L3 直通后 TUN 实际地址 = 核按
	// 设备身份派生的第二地址；配置里的虚拟 IP 已彻底退役（没有回退值可打，拿不到
	// 派生地址就是异常，如实打 `?` 而不是拿一个不存在的地址糊弄排查的人）。
	if ip := derivedTunIP(t); ip != "" {
		logf("running (mtu=%d tunIp=%s)", cfg.MTU, ip)
	} else {
		logf("running (mtu=%d tunIp=?)", cfg.MTU)
	}

	// ---- 等 attach：拿到 fd 之前不碰任何 fd 相关的东西 ----
	var fd int
	select {
	case fd = <-run.attachCh:
	case <-run.stop:
		run.setStageIfCurrent(stageIdle, "stopped", "被停止请求中断", false)
		logf("prepare 就绪后、attach 之前收到停止信号，收工")
		reclaimAttachFd(run, logf)
		return nil
	case <-time.After(attachDeadline):
		// 防止单飞锁被"无人推进的世代"长期占住（见 design 决策 5）
		run.setStageIfCurrent(stageIdle, "attach-timeout", "就绪后无人 attach，已自行收工放锁", false)
		logf("prepare 后 %v 内没有 attach，自行收工并释放单飞锁（状态回 idle）", attachDeadline)
		reclaimAttachFd(run, logf)
		return nil
	}
	// **不用 os.NewFile**（2026-09-14 改）：`os.NewFile` 会给这个 fd 注册一个"GC 时关掉 fd"的
	// finalizer，而 fd 的所有权其实在扩展（系统框架）手里 —— 扩展 destroy 之后 fd 号可能被复用，
	// 某次 GC 就可能把**新隧道**的 fd 关掉。裸 fd 读写让 Go 完全不持有它、也就永远不会 close 它，
	// 所有权从此明确单一（见 AGENTS 坑 50）。
	// ⚠️ 注意：**不要**用 fstat/Stat 当"坏 fd"的判据 —— OHOS 沙箱会拒绝对 VPN tun fd 做 fstat
	//（真机实测 `stat tun: permission denied`），而那个 fd 的读写完全正常（曾因此把一次成功的
	// 启动判成失败）。真正的 fd 失效由两条 fd 循环报错暴露（markUnhealthy）。
	logFdInfo(logf, fd) // 内部自己 fstat：失败只记一行诊断，不影响启动
	// fd 的所有权在扩展/系统框架（坑 50 的结论不变）：NewTunFromFD 只包读写、不 close；
	// fd 失效由 hub 的错误回调暴露（上面挂的 markUnhealthy）。
	if aerr := attacher.AttachFD(fd, int(cfg.MTU)); aerr != nil {
		run.setStageIfCurrent(stageFailed, "attach", aerr.Error(), false)
		return fmt.Errorf("attach 失败：%w", aerr)
	}
	run.setStageIfCurrent(stageAttached, "", "", meowed)
	logf("attached（数据面已接管 fd=%d，L3 直通）", fd)

	// 回环桥（app_bridge.go）：attached 后才起——语义即「会话在桥在」；单座失败只记
	// 状态、不阻断隧道（含 bind 有界重试）。收工顺序（defer LIFO）：先关桥监听，
	// 之后的 closeDNSPool/teardownNetstack/closeClientOnce 依次收尾，残留的桥接连接
	// 随客户端关闭自然断掉。
	t.setPortForwards(cfg.PortForwards)
	t.bridge = newBridgeHost("隧道桥", bridgeDirFromCfg(cfg), logf, func(ctx context.Context, port uint16) (net.Conn, error) {
		return t.cl.DialTCPPort(ctx, port)
	}, t.dialTimeout)
	t.bridge.start()
	defer t.stopPortForwards()
	defer t.bridge.stop()

	// connectResultLine — 建连结果行（openspec direct-first-endpoint-hint 任务 3.2）：
	// 三种可检索结果 hint-hit / hint-miss→derp|relay / no-hint，附候选档位与
	// 超 TTL 跳过数。path 是第一次链路采样的路径（direct/derp/relay）。

	// 链路巡检：固定 60s 探一次对端，并把**当前数据面路径 + 往返**打进日志。
	// 两个目的：
	//   ①可达性——`running` 只说明本方组线完成，若与出口不在同一 DERP 区域，数据面其实是死的
	//     （Ping 一直不返回）；连续 3 次无响应就标记不健康，界面据此显示断开而不是谎报已连接。
	//   ②保活——探测包刷新 NAT/CGNAT 的 UDP 映射、维持出口侧对手机直连地址的路径信任
	//     （空闲无流量时它是唯一来源，见 silent disco 的取舍）。
	// 界面新鲜度不在此列：扩展读的是本巡检写入的状态快照（前台每 5s 读一次，纯读不触发
	// 探测），快照最多落后一个间隔；用户注视恢复的时点（连接完成 / 回前台）另有立即探测补上。
	//
	// 待发包下推器（demand-driven-recovery D4）：App 出站新鲜 + 接收静默 → 立即异步
	// 下推阶梯，不等本巡检的 60s 拍（与巡检互补，跟随同一世代）。
	startDemandPusher(run, cl, logf)
	go func() {
		// panic 兜底（review 复审补全 #19）：巡检 goroutine 一旦 panic 会把整个扩展
		// 进程带走（c-shared 没有第二道防线）。恢复并标记不健康，让扩展走既有重建。
		defer func() {
			if rec := recover(); rec != nil {
				logf("⚠️ 链路巡检 panic（已恢复并标记不健康，交由扩展重建）：%v", rec)
				t.markUnhealthy("panic")
			}
		}()
		const perTry = 10 * time.Second
		failStreak := 0
		relayStreak := 0             // 连续停留在中继的巡检拍数（见 relayUpgradeEvery）
		var lastRegRefresh time.Time // 上次补发注册的时刻（见 hostsession.ShouldRefreshReg / RegRefreshEvery）
		var lastLoopAt time.Time     // 上一拍时刻（挂起空窗检测的基线，见 hostsession.SuspendGapDetected）
		var busy atomic.Bool
		// demand-driven-recovery（2026-09-23 弹窗事故整改）：
		//   - lastCountedFail：上一次**计入证据**的失败时刻——「连败」带时间窗（相邻计数
		//     失败间隔超过 10 分钟窗即作废重来），计数不得跨长时间挂起拼凑
		//     （事故里 1/3、2/3、3/3 横跨三小时正是靠这个堵住）；
		//   - gateGated：失败被需求门控拦下的边沿状态（进入拦下态一行、期间静默、
		//     需求恢复一行——不随 5s/60s 泵刷屏）。
		var lastCountedFail time.Time
		gateGated := false
		// localNoiseSince：本地错误连续持续的起点（长停逃逸的基线，见 hostsession.NoiseEscalated）。
		var localNoiseSince time.Time
		// probeNow：这一轮不等巡检间隔、立即探测。初始 true（attach 完就立即探——
		// 界面链路条不必空等第一个间隔）；自重绑成功后也置 true（立刻补一条 link: 行）。
		probeNow := true
		for {
			if !probeNow {
				timer := time.NewTimer(patrolInterval)
				select {
				case <-run.stop:
					timer.Stop()
					logf("链路巡检退出（隧道已停止）")
					return
				case <-patrolKick:
					// 回到前台：立刻探一次，别让界面等一个巡检间隔
					timer.Stop()
					logf("链路巡检：App 回到前台，立即探测一次")
				case <-timer.C:
				}
			}
			probeNow = false
			select {
			case <-run.stop:
				logf("链路巡检退出（隧道已停止）")
				return
			default:
			}
			// 挂起空窗检测（openspec recovery-ladder）：本拍实际间隔远超巡检周期 = 进程
			// 被系统冻结过（服务腿巡检 app_service.go 同款判据）。唤醒后会话大概率已死
			// （>180s 必死）、socket 可能已失效——不等本拍探测失败，直接从轻档起跑阶梯。
			// 起 goroutine：本拍探测照常进行，两者由阶梯单飞合并。
			nowAt := time.Now()
			if hostsession.SuspendGapDetected(lastLoopAt, nowAt, patrolInterval) {
				logf("巡检空窗 %v（判为进程被挂起）→ 阶梯恢复", nowAt.Sub(lastLoopAt).Round(time.Second))
				go runRecoverAt(recoverR1, "挂起唤醒")
			}
			lastLoopAt = nowAt
			if busy.Load() {
				continue
			}
			// 需求信号的出站计数在拍头取走清零（自上一拍以来的 App 出站 = 本拍需求的
			// TUN 位；hub 计数，挂起期读循环冻结、取走值只反映醒着的窗口）。
			// 发送统计同拍取走：评审 3-1 的「全候选本地失败 ⇒ 环境性禁发」判据
			//（覆盖非采纳/赛跑态下采纳路径粘性信号够不着的盲区）。
			// 注意取走在 busy 检查**之后**（评审 4）：busy 复活的形态下先取走再
			// continue 会把已取走的计数静默吞掉、该拍需求误判为无。
			patrolOutPkts := int64(0)
			sendTries, sendLocalFails := int64(0), int64(0)
			if tr := newTransport(cl); tr != nil {
				patrolOutPkts = tr.SwapTunOutboundPackets()
				sendTries, sendLocalFails = tr.SwapSendStats()
			}
			// 握手卡死自愈：直连路径的首个握手响应丢过一次之后，WireGuard 会一直重发
			// 同一个 initiation，而响应方按防重放整条丢掉 ⇒ 双方僵到「下次有数据要发」
			// 才恢复（真机实测约 90s 黑洞）。这里每拍检查一次 wireguard 自己的状态：
			// 正在重试、或很久没有完成过握手，就重新武装一次（下一次出站消息发起全新
			// 握手，响应方会接受）。
			busy.Store(true)
			type patrolRes struct {
				err error
				// rtt：这条探测（拨出口 1 号端口 → 拿到 connection refused）的往返 —— 界面「xx ms」就是它。
				// 原来两个 setLink 调用点的 RTT 参数写死 0，界面永远显示「—」（2026-09-20 用户反馈）。
				rtt time.Duration
			}
			done := make(chan patrolRes, 1)
			go func() {
				// 外面再兜一层超时（双保险）：新栈 PathProbe = wgnet 的 ctx 拨号（到期即时
				// 关端点），本身有界；这层兜的是收工竞态里栈/fd 关闭瞬间的极端卡顿。
				ctx, cancel := context.WithTimeout(context.Background(), perTry)
				defer cancel()
				started := time.Now()
				err := cl.PathProbe(ctx)
				done <- patrolRes{err, time.Since(started)}
			}()
			var err error
			var rtt time.Duration
			select {
			case r := <-done:
				err = r.err
				rtt = r.rtt
			case <-time.After(perTry + 2*time.Second):
				err = errors.New("链路巡检超时（对端不可达）")
			}
			busy.Store(false)
			// 旁路观测（endpoint-freshness）：每拍对候选全集发带 pad 的载荷探测，应答端点
			// 列表进学习缓存（SourceProbe，非认证线索）。**旁路纪律**：它只写缓存与日志，
			// 不碰下面的 err/failStreak/健康判定——候选全集里的死地址必然失败，那不是故障。
			if tr := newTransport(cl); tr != nil {
				go func() {
					defer func() {
						if rec := recover(); rec != nil {
							logf("⚠️ 旁路探测 panic（已恢复；仅缓存保鲜受影响）：%v", rec)
						}
					}()
					pctx, pcancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer pcancel()
					tr.ProbeCandidates(pctx)
				}()
			}
			if err == nil {
				// 链路快照：新栈直接取 Transport.Status()（via=direct|relay|none + ep）
				if tr := newTransport(cl); tr != nil {
					// 存活探测刚成功：该路径完成了一次真实往返 → 落已验证
					//（覆盖「R3 救回后闲置、无隧道内拨号」的窗口，评审 C-2/②-4）。
					tr.NotePathAlive()
					st := tr.Status()
					t.setLink(st.Via, st.Ep, rtt.Milliseconds())
					logf("link: via=%s ep=%s rtt=%dms（新栈状态快照）", st.Via, st.Ep, rtt.Milliseconds())
					// 停留中继时的**定期直连重试**：路径一旦选定就是单路径发送（只发采纳地址），
					// 所以"中继先回、直连其实也可达"会一直走中继 —— 每隔 relayUpgradeEvery 拍
					// 重新武装一次赛跑（清采纳 + 下一发出站包镜像到全部候选，含直连），
					// 直连通就自然翻上去，不通就继续停留中继（成本：几包镜像）。
					relayStreak = relayUpgradeStreak(st.Via, relayStreak)
					if relayUpgradeDue(st.Via, relayStreak) {
						relayStreak = 0
						logf("RELAY-UPGRADE：已在中继停留 %v，重新武装赛跑试直连（下一发出站包镜像到全部候选）",
							(relayUpgradeEvery * patrolInterval).Round(time.Second))
						tr.RearmSoft() // 软赛跑：中继立即参与（升级失败也不中断在用路径）
						uctx, ucancel := context.WithTimeout(context.Background(), perTry)
						ustarted := time.Now()
						uerr := cl.PathProbe(uctx) // 这一发探测包就是"镜像出去试直连"的出站包
						urtt := time.Since(ustarted)
						ucancel()
						if uerr == nil {
							if st2 := tr.Status(); st2.Via != st.Via {
								logf("RELAY-UPGRADE：升级成功 → via=%s ep=%s rtt=%dms", st2.Via, st2.Ep, urtt.Milliseconds())
								t.setLink(st2.Via, st2.Ep, urtt.Milliseconds())
							}
						}
					}
				}
			}
			// 周期补发注册（demand-driven-recovery 1.7：从探测成功分支移出——失败拍也照发。
			// 注册走原始 UDP、不依赖 WG 会话与探测结果；此前失败拍靠阶梯 R1 的补注册顺带，
			// 无需求期的失败拍不起阶梯后就断了保活）。
			if tr := newTransport(cl); tr != nil && hostsession.ShouldRefreshReg(lastRegRefresh, time.Now()) {
				if tr.RefreshReg() {
					lastRegRefresh = time.Now()
				}
			}
			// ---- 失败证据的需求门控（openspec demand-driven-recovery） ----
			// 需求判定在证据消费前做（本拍出站计数已在拍头取走）；本地发送错误用 Bind 的
			// 粘性信号（探测 err 拿不到 errno——写错误不回传拨号方，恒是超时）。
			// 成功拍也走同一纯函数（评审 H3：成功清零，F,S,F,F 停在 2——不在这里单独清）。
			demand, demandWhy := patrolDemand(patrolOutPkts, time.Now())
			noteDemand(demand, demandWhy, time.Now())
			// 环境噪声判据（两路或）：① 采纳路径粘性信号（15s 尾窗，快路径）；
			// ② 本拍发送尝试全部本地失败（粒度与需求对齐——挂起禁发时全候选皆败；
			// 蜂窝下 LAN 候选必然 ENETUNREACH 但中继发得出去 ⇒ 不算）。
			localNoise := sendTries > 0 && sendLocalFails == sendTries
			if !localNoise {
				if tr := newTransport(cl); tr != nil {
					localNoise = tr.LocalSendErrWithin(perTry + 5*time.Second)
				}
			}
			// 长停逃逸（评审 4 中-1，共享纯函数 hostsession.NoiseEscalated）：
			// 本地错误持续超过阈值 ⇒ 不再按环境噪声抑制——大概率是采纳路径本身
			// 发不出去（换网后陈 LAN 地址），走正常升级链（R3 清采纳是解药）；
			// 挂起禁发通常分钟内随环境恢复解除，到不了这里。
			if esc, ns := hostsession.NoiseEscalated(localNoise, localNoiseSince, time.Now()); esc {
				logf("本地发送错误持续 %s（长停逃逸）：按质量失败计，进入正常升级链",
					time.Since(localNoiseSince).Round(time.Second))
				localNoise = false
				localNoiseSince = ns
			} else {
				localNoiseSince = ns
			}
			// 赋值而非 `failStreak, counted := ...`：循环体是新块，:= 会 shadow 外层
			// failStreak（真机复验实测：shadow 后每拍计数恒 1，三连败永远到不了）。
			newStreak, counted := hostsession.PatrolEvidenceGate(localNoise, demand, failStreak, lastCountedFail, time.Now(), err)
			failStreak = newStreak
			if err != nil {
				if !counted {
					// 环境噪声（挂起禁发）/ 零流量需求期：该拍失败不构成路径质量证据。
					// 清零（不是「不加」）——无需求拍夹在中间时，两端的失败不得拼成连败。
					why := demandWhy
					if localNoise {
						why = "本地发送错误（环境噪声）"
					}
					if !gateGated {
						gateGated = true
						logf("巡检失败被门控拦下（%s）→ 计数清零仅记录", why)
					}
				} else {
					if gateGated {
						gateGated = false
						logf("需求恢复（%s）：巡检失败重新计入证据", demandWhy)
					}
					lastCountedFail = time.Now()
					logf("对端巡检失败 %d/3: %v", failStreak, err)
					// 失败当拍进恢复阶梯（openspec recovery-ladder，R1 起跑 = 补注册 + 丢会话，
					// 保采纳）：出口重启（设备表清空）/ 本设备记录被回收时手机侧没有别的信号，
					// 原本要等 3 连败后的整套自重绑（≈2–4 分钟），现在本次巡检内就能恢复。
					// 丢会话仍是关键：本地会话此时往往"看起来还有效"（≤120s 才 rekey），
					// 不主动丢会话就会一直用对端已丢失的密钥发包、谁都不握手。
					// （无需求拍不触发：清零分支已拦。）
					if rc := runRecoverAt(recoverR1, "巡检失败"); rc == 0 {
						logf("巡检失败后阶梯已恢复（不用等 3 连败）")
						failStreak = 0
						continue
					}
				}
			} else if gateGated {
				// 成功拍：门控态结束的边沿（期间静默；计数已由纯函数清零）。
				gateGated = false
				logf("巡检恢复：门控态结束（成功拍清零）")
			}
			if failStreak >= 3 {
				// 3 连败从换源档（R2）起跑阶梯（自动升 R3 重赛跑）——后台/熄屏冻结唤醒后
				// 旧 socket 常已失效，但 TUN fd、Go 核、系统 VPN 都还在，重绑足以恢复，
				// 不必整套重建（拆系统 VPN 状态栏会闪、还要重走两阶段启动）。
				logf("对端连续 3 次不可达，进恢复阶梯（R2 换源起跑，不拆隧道）")
				if rc := runRecoverAt(recoverR2, "巡检3连败"); rc == 0 {
					logf("阶梯恢复成功（巡检 3 连败后），对端恢复可达，继续巡检")
					failStreak = 0
					probeNow = true
					continue
				}
				logf("阶梯未恢复，标记隧道不健康（交给扩展重建）")
				t.markUnhealthy("patrol")
				return
			}
		}
	}()

	// 周期统计：与 /proc/net/dev vpn-tun 行对表。
	// 必须跟着本世代一起退出：重建隧道时旧核的 fd 已失效、计数冻结，若这个定时器不退，
	// 它会继续往同一个日志文件里打旧数字 —— 日志里出现两份交错的 stats 行，
	// `tail -1` 有可能取到冻结的那份，排查时会被带偏（实测踩过）。
	go func() {
		// panic 兜底（同巡检，review 复审补全 #19）：只影响日志，恢复即可。
		defer func() {
			if rec := recover(); rec != nil {
				logf("⚠️ 统计 goroutine panic（已恢复；仅日志受影响）：%v", rec)
			}
		}()
		tick := time.NewTicker(time.Duration(cfg.StatsSecs) * time.Second)
		defer tick.Stop()
		elapsed := 0 // 本世代已运行的秒数
		baseDone := false
		lastDiag := 0 // 上次打 fd 快照时的 elapsed
		for {
			select {
			case <-tick.C:
				elapsed += cfg.StatsSecs
				t.refreshFdStats()
				logf("stats: %s", t.st.String())
				// 基线一行 + （可选）周期快照；默认只打基线，见 DiagFdSecs 注释。
				// 用"距上次 >= 间隔"而不是取模：DiagFdSecs 不是 StatsSecs 的整数倍时，
				// 取模几乎永远不相等（原来的写法在那种配置下等于永远不打快照）。
				if !baseDone || (cfg.DiagFdSecs > 0 && elapsed-lastDiag >= cfg.DiagFdSecs) {
					logf("fd: %s", fdSnapshot())
					baseDone = true
					lastDiag = elapsed
				}
			case <-run.stop:
				return
			}
		}
	}()

	// 扩展要重建隧道（网络切换/核心失联）时会关闭本世代的 stop，这里收工并回收资源。
	select {
	case <-run.stop:
		logf("tier-core: 收到停止信号，正在回收（client/stack）")
		// 暖机阶段的 `up()`（拉地图/起引擎/meow 注册）可能不理会 context 地卡住（实测 >90s），
		// 它要等下面 cl.Close() 关掉底层连接才会退出 —— 这行日志用来确认还有没有它悬着。
		// （勘误：库的 `ping` 本身是 select ctx 的、自带 10s 上限；真正会卡住的是 ensureStarted 那段。）
		select {
		case <-warmDone:
		default:
			logf("暖机仍未返回（ensureStarted/Ping 卡住，随 client 关闭回收）")
		}
	}
	// client 与 netstack 的回收由上面的 defer 负责（所有退出路径一致）
	return nil
}

// derivedTunIP：本世代的应用面派生地址（wgcore.Core.TunIP；空串 = 会话还没建好）。
func derivedTunIP(t *tunRunner) string {
	if t == nil || t.cl == nil {
		return ""
	}
	if tp := newTransport(t.cl); tp != nil && tp.Core() != nil {
		if ip := tp.Core().TunIP(); ip.IsValid() {
			return ip.String()
		}
	}
	return ""
}

// reclaimAttachFd 收走 attachCh 里可能已经被塞进来的 fd（**只收走、不关闭**）。
//
// 竞态背景（2026-09-14 发现）：attach 与 stop/超时同刻就绪时 select 随机选分支，
// fd 可能已进 chan 而没人接管。但 review #14 修正了处置方式：fd 的所有权在扩展
// （系统框架发牌）——核在收工路径上 unix.Close 它，若此刻扩展已 destroy 并复用了
// 该 fd 号，就会关掉**别的**东西。正确语义：收走让 chan 排空（避免下一个世代读到
// 陈旧 fd），fd 本身留给扩展的 connection.destroy() 随系统回收（attachTun 在
// stageIdle 时返回 -4，扩展的失败路径必然走 destroy）。
func reclaimAttachFd(run *tunRun, logf Logf) {
	select {
	case fd := <-run.attachCh:
		logf("attach 与收工竞态：已收回未被接管的 fd=%d（不关闭——所有权在扩展，由 destroy 回收）", fd)
	default:
	}
}

// attachTun 两阶段启动的第二阶段：把 TUN fd 递给处于 ready 的世代。
// 返回 0 已接管 / -1 没有处于 ready 的世代（没 prepare、已在接管、或已收工）/ -4 接管失败
// （此时世代已整体收工，失败原因可从 tunStatusJSON 读到）。
func attachTun(fd int) int {
	r := currentTunRun()
	if r == nil || probeRunning.Load() == 0 {
		return -1
	}
	if st, _, _, _ := tunStageSnapshot(); st != stageReady {
		return -1
	}
	select {
	case r.attachCh <- fd:
	case <-time.After(2 * time.Second):
		return -1
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		switch st, _, _, _ := tunStageSnapshot(); st {
		case stageAttached:
			return 0
		case stageFailed, stageIdle:
			return -4
		}
		time.Sleep(20 * time.Millisecond)
	}
	// -5：**轮询超时**，与 -4（世代真的失败/收工）区分开 —— 原先两者都是 -4，
	// 扩展只能看到"接管失败"，而其实只是"慢"（5s 内没等到 attached）。
	return -5
}

// tunStopWait：通知 tun 循环收工并等待（有界）。扩展重建隧道前必须调用，
// 否则 Go 核的单飞锁（probeRunning）会拒绝下一次 ClientCoreTunStart。
// （cgo 的 C 命名空间按文件隔离，故这里只返回 int，由 probe_lib.go 包成 C.int。）
// 换网/唤醒的就地恢复已整体收编到 recover.go 的恢复阶梯（ClientCoreTunRecover）。

// errActionTimeout/runBoundedAction 已随迁 hostsession（r4 订正：随迁、包内未导出——
// 796c0fb 实测调用点全在随迁的共享阶梯 recover.go 内，本包无调用点残留，故无壳）。

// tunLogf 取本世代 tunRunner 的 logger（带 `tier-core: ` 前缀，与其它核日志同一格式）。
func tunLogf(r *tunRun) Logf {
	if tr := r.runner(); tr != nil && tr.logf != nil {
		return tr.logf
	}
	return Discard
}

func tunStopWait() int {
	r := currentTunRun()
	if r == nil || probeRunning.Load() == 0 {
		return 0
	}
	select {
	case <-r.done:
		return 0 // 本世代早已退出
	default:
	}
	r.stopOnce.Do(func() { close(r.stop) })
	// preparing 阶段没有 fd 也没有读循环可打断，而暖机可能卡在不理会 context 的 up()/ensureStarted 上
	// （实测 >90s）：**关掉客户端**是最可靠的第二条打断路径。
	if st, _, _, _ := tunStageSnapshot(); st == stagePreparing {
		r.closeClientOnce()
	}
	select {
	case <-r.done:
		return 0
	case <-time.After(3 * time.Second):
		// 收工超时（例如阻塞在 fd 读上，close 打不断阻塞读）：
		// 只要这期间没有新世代启动，就强制放锁——否则重建会永远卡在 ClientCoreTunStart rc=-1。
		if r.isCurrent() {
			tunUnhealthyWhy.Store("stop") // 收工超时：同世代退出类
			tunHealthy.Store(false)
			probeRunning.Store(0)
			return -2
		}
		return -1
	}
}

// pipeBoth 双向转发并做半关闭：上游/应用任一方向 EOF 只关对应写方向，
// 让 FIN 语义能穿透（HTTP/1.0 响应靠 FIN 结尾，直接双向收口会截断响应）。
func pipeBoth(logf Logf, a, b net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	cp := func(dst, src net.Conn, done chan<- struct{}) {
		n, err := io.Copy(dst, src)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			logf("pipe %v→%v: %v after %dB", src.RemoteAddr(), dst.RemoteAddr(), err, n)
		}
		if hc, ok := dst.(closeWriter); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	done := make(chan struct{}, 2)
	go cp(a, b, done)
	go cp(b, a, done)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// tunAttachSurface L3 attach 面（wgcore.Core 的能力，经 newSession 透出）。
type tunAttachSurface interface {
	AttachFD(fd, mtu int) error
	SetOnTunError(f func(err error))
	FdStats() (read, write int64)
}

func tunAttachSurfaceOf(cl exitSession) (tunAttachSurface, bool) {
	a, ok := cl.(tunAttachSurface)
	return a, ok
}
