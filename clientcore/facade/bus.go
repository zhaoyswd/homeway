package facade

// bus.go — 事件总线（§3.4，spec「事件流」）：全局单调 seq（每次启动从 0 计、随
// 代际唯一化）+ 环形重放窗（默认 4096 条 / 1MiB，可注入）+ 域过滤分发 + 游标回放。
//
// 锁序三路径（design D5 / r1 A4）：
//   ①发射：调用方在会话临界区尾部调 Publish（会话锁 → 总线锁单向；本包不回头调
//     任何会话锁）；
//   ②快照：snapshot.get 由连接层先取 Backend 快照、**最后**读 CurrentSeq（本包
//     不参与——见 server.go handleSnapshotGet）；
//   ③分发：总线锁内只拷贝订阅者 channel 引用，投递（chan 非阻塞 send）在锁外。
//
// 限速在取号之前（spec：总线上已发事件的序号无空洞）：transfer（每 host 默认 1s
// 一拍）与 log（1s 窗口内有界尾配额）的丢弃不占号——「1s 一拍」按主机采样节拍的
// 自然语义（per-host），「有界尾」按窗口内最多 N 条（突发日志只放最近 N 条进总线，
// 其余丢弃——压低环形窗被 log 冲刷的压力，状态域优先保窗）。
//
// 每订阅者队列有界（默认 512）：投递失败不静默丢——标记 overrun 并关闭 sub.Done()
// （连接层收到即发 goodbye(overrun) 断连，前端 resubscribe + 全量重快照恢复）。
// 「不重不漏」因此对**总线已发事件**是无条件承诺（在线 = 送达或断连；断连后续播
// 依赖重放窗 + 代际）。
//
// 投递次序说明：投递在总线锁外，跨发布者的并发事件到达顺序不保证全局 seq 单调；
// 事件自包含（带 seq），前端按同键比 seq 幂等覆盖（at-least-once 语义）。同一
// 发布者的同键事件天然串行（hostsession 的 Observer 在会话状态迁移尾部同步调用）。
// 订阅回放不经投递通道：Subscribe 锁内拷入 pending 回放段，订阅者消费顺序固定
// **pending → ch**（B3 订阅原子交付——「回放批先于任何在线事件」的总线侧保证）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// 总线默认参数（design D5 / Open Questions：真机数据再调，不改契约形状）。
const (
	DefaultRingEntries = 4096
	DefaultRingBytes   = 1 << 20 // 1MiB
	DefaultSubQueue    = 512
	DefaultLogBurst    = 20 // log 域 1s 窗口内最多放行条数（有界尾）
)

// 总线哨兵错误（订阅路径，server 层映射到错误码）。
var (
	// ErrCursorStale 订阅游标过旧（超出环形重放窗）或代际失配 → cursor_stale
	// （resync 语义：前端全量重快照，MUST NOT 静默跳段）。
	ErrCursorStale = errors.New(CodeCursorStale)
	// ErrCursorFuture 游标超前于当前序号（值域外）→ bad_request。
	ErrCursorFuture = errors.New("cursor 超前于当前序号")
)

// Event 总线里的一条事件（= EventBody 的内存形态；payload 为该 kind 的载荷 JSON）。
type Event struct {
	Seq     uint64
	Domain  string
	Kind    string
	Payload json.RawMessage
}

// BusConfig 总线参数（零值 = 全默认；测试注入调小环/队列）。
type BusConfig struct {
	RingEntries   int
	RingBytes     int
	SubQueue      int
	TransferEvery time.Duration // transfer 域每 host 采样节拍（默认 1s）
	LogBurst      int           // log 域 1s 窗口配额（默认 DefaultLogBurst）
	Now           func() time.Time
}

// Bus 进程内单例事件总线。
type Bus struct {
	mu  sync.Mutex
	gen string

	seq        uint64 // 已发出的最大序号（下一个 = seq+1）
	ring       []Event
	ringStart  int // 环内最老元素的起始下标
	ringLen    int
	ringBytes  int // 环内 payload 字节量（第二上限）
	ringCap    int
	ringMaxBy  int
	subQueue   int
	transferEv time.Duration
	logBurst   int
	now        func() time.Time

	transferLast map[string]time.Time // per-host 上次放行时刻
	logTimes     []time.Time          // log 域 1s 窗口内放行时刻（有界尾计数）

	subs map[*Subscriber]struct{}
}

// NewBus 建总线。gen = 本次守护进程启动的代际（每次启动随机，前端持旧代际游标
// 订阅将得到 cursor_stale）。
func NewBus(gen string, cfg BusConfig) *Bus {
	fill := func(v, def int) int {
		if v <= 0 {
			return def
		}
		return v
	}
	if cfg.TransferEvery <= 0 {
		cfg.TransferEvery = time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Bus{
		gen:          gen,
		ring:         make([]Event, fill(cfg.RingEntries, DefaultRingEntries)),
		ringCap:      fill(cfg.RingEntries, DefaultRingEntries),
		ringMaxBy:    fill(cfg.RingBytes, DefaultRingBytes),
		subQueue:     fill(cfg.SubQueue, DefaultSubQueue),
		transferEv:   cfg.TransferEvery,
		logBurst:     fill(cfg.LogBurst, DefaultLogBurst),
		now:          cfg.Now,
		transferLast: make(map[string]time.Time),
		subs:         make(map[*Subscriber]struct{}),
	}
}

// Generation 当前代际。
func (b *Bus) Generation() string { return b.gen }

// CurrentSeq 当前已发出的最大序号（快照序号源；无事件 = 0）。
func (b *Bus) CurrentSeq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

// Publish 发布一条事件（词表外 domain/kind 报错；term 域载荷字段初始集为空——
// 只接受 nil/空载荷）。返回发出序号。session.diag 的「本期不发射」硬闸已随 4a
// §6.3 拆除（词表与载荷字段不动：host, reason——reason 值域 gated/budget/
// probe_window 只增不改；老前端不识该 kind 按未知值忽略的既有纪律不变）。
func (b *Bus) Publish(domain, kind string, payload any) (uint64, error) {
	if kindDomains[kind] == "" {
		return 0, fmt.Errorf("词表外事件 kind %q", kind)
	}
	if kindDomains[kind] != domain {
		return 0, fmt.Errorf("kind %q 不属于域 %q（归属 %q）", kind, domain, kindDomains[kind])
	}
	var raw json.RawMessage
	if payload != nil {
		switch p := payload.(type) {
		case json.RawMessage:
			raw = p
		default:
			b, err := json.Marshal(payload)
			if err != nil {
				return 0, err
			}
			raw = b
		}
	}
	if domain == DomainTerm && len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
		return 0, fmt.Errorf("term 域载荷字段初始集为空（收到 %d 字节），字段名由后续 delta 增补", len(raw))
	}
	ev := Event{Domain: domain, Kind: kind, Payload: raw}
	return b.publish(ev)
}

// PublishTransfer 发布 transfer.sample：**取号前**做每 host 节拍限速（默认 1s 一拍，
// 窗内的后续采样丢弃、不占号——seq 无洞）。ok=false = 被限速丢弃。
func (b *Bus) PublishTransfer(p TransferSamplePayload) (seq uint64, ok bool) {
	now := b.now()
	b.mu.Lock()
	if last, have := b.transferLast[p.Host]; have && now.Sub(last) < b.transferEv {
		b.mu.Unlock()
		return 0, false // 丢弃发生在取号之前
	}
	b.transferLast[p.Host] = now
	b.mu.Unlock()
	raw, err := json.Marshal(p)
	if err != nil {
		return 0, false
	}
	seq, err = b.publish(Event{Domain: DomainTransfer, Kind: KindTransferSample, Payload: raw})
	if err != nil {
		return 0, false
	}
	return seq, true
}

// PublishLog 发布 log.line：**取号前**做窗口有界尾限速（1s 窗口内最多 logBurst 条，
// 超出丢弃、不占号）。ok=false = 被限速丢弃。
func (b *Bus) PublishLog(p LogLinePayload) (seq uint64, ok bool) {
	now := b.now()
	b.mu.Lock()
	cut := now.Add(-time.Second)
	keep := b.logTimes[:0]
	for _, t := range b.logTimes {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	b.logTimes = keep
	if len(b.logTimes) >= b.logBurst {
		b.mu.Unlock()
		return 0, false // 窗口配额满：丢弃发生在取号之前（保状态域优先占窗）
	}
	b.logTimes = append(b.logTimes, now)
	b.mu.Unlock()
	raw, err := json.Marshal(p)
	if err != nil {
		return 0, false
	}
	seq, err = b.publish(Event{Domain: DomainLog, Kind: KindLogLine, Payload: raw})
	if err != nil {
		return 0, false
	}
	return seq, true
}

// publish 取号 + 入环 + 分发（锁内取号入环并拷贝订阅者引用，投递在锁外）。
func (b *Bus) publish(ev Event) (uint64, error) {
	b.mu.Lock()
	b.seq++
	ev.Seq = b.seq
	// 入环（两个上限：条数环形 + payload 字节量；字节量超限先淘汰最老直至装得下
	// 或环空——环形窗淘汰只影响重放，不影响已发事件的 seq 连续性）。
	for b.ringLen == b.ringCap || (b.ringLen > 0 && b.ringBytes+len(ev.Payload) > b.ringMaxBy) {
		b.evictLocked()
	}
	tail := (b.ringStart + b.ringLen) % b.ringCap
	b.ring[tail] = ev
	b.ringLen++
	b.ringBytes += len(ev.Payload)
	// 拷贝匹配订阅者的（订阅者, 投递口）对（锁外投递）。
	type target struct {
		sub *Subscriber
		ch  chan Event
	}
	targets := make([]target, 0, len(b.subs))
	for sub := range b.subs {
		if sub.matches(ev.Domain) {
			targets = append(targets, target{sub: sub, ch: sub.ch})
		}
	}
	b.mu.Unlock()
	for _, t := range targets {
		select {
		case t.ch <- ev:
		default:
			// 队列满 = 慢消费者：不静默丢。停投该订阅者（先从总线摘除，再标记
			// overrun 并关闭停止信号——连接层收到即发 goodbye(overrun) 断连）。
			b.Unsubscribe(t.sub)
			t.sub.terminateOverrun()
		}
	}
	return ev.Seq, nil
}

// evictLocked 淘汰环内最老一条。调用方持锁。
func (b *Bus) evictLocked() {
	if b.ringLen == 0 {
		return
	}
	old := b.ring[b.ringStart]
	b.ring[b.ringStart] = Event{}
	b.ringStart = (b.ringStart + 1) % b.ringCap
	b.ringLen--
	b.ringBytes -= len(old.Payload)
}

// oldestSeq 环内最老事件的 seq（环空 = 0）。调用方持锁。
func (b *Bus) oldestSeqLocked() uint64 {
	if b.ringLen == 0 {
		return 0
	}
	return b.ring[b.ringStart].Seq
}

// Subscriber 一个连接的订阅态（ch 有界；满 = overrun）。
type Subscriber struct {
	bus     *Bus
	domains map[string]bool
	// pending 订阅回放段（B3，r2 新-3 拍死唯一形态）：Subscribe 在总线锁内把
	// 回放拷进本切片（**普通切片，不占订阅队列 ch**——锁内灌 ch 形态被否决：
	// ch 已满〔慢消费者或门闩期 writer 不消费〕时会在总线锁内阻塞 channel send，
	// Publish 全线挂起，而 hostsession 的 Observer 在状态迁移尾部同步调 Publish
	// = 会话面挂死；非阻塞 + overrun 则 terminateOverrun 重入 b.mu 自锁）。
	// 消费顺序固定 **pending → ch**：绑定层在订阅确认写出且门闩清位后经
	// DrainPending 取走（先排空 pending、再补写暂存缓冲、再恢复常规消费）。
	// 替换订阅时 = **覆盖**（新回放段取代旧段——前端按 seq 幂等去重无损，
	// r3 低-2）。
	pending []Event
	// view 订阅视图声明原文（D5 源③：文法 host=<id>[,host=<id>]*，ParseView 解析；
	// 随 Subscribe 原子替换——与 domains 同一注册点）。
	view    string
	ch      chan Event
	stop    chan struct{}
	overrun bool
	once    sync.Once
}

// NewSubscriber 建订阅者（未挂到总线；bus.Subscribe 时生效）。
func (b *Bus) NewSubscriber() *Subscriber {
	return &Subscriber{
		bus:  b,
		ch:   make(chan Event, b.subQueue),
		stop: make(chan struct{}),
	}
}

// Events 在线事件流（读取端）。
func (s *Subscriber) Events() <-chan Event { return s.ch }

// Done 关闭 = 订阅被总线终止（当前唯一原因 = overrun；连接层发 goodbye 断连）。
func (s *Subscriber) Done() <-chan struct{} { return s.stop }

// OverrunDone 是否因 overrun 终止。
func (s *Subscriber) OverrunDone() bool { return s.overrun }

// matches 域过滤（空集合 = 未订阅任何域）。
func (s *Subscriber) matches(domain string) bool { return s.domains[domain] }

// Subscribe 挂订阅 + 游标回放（原子：锁内检查游标、回放拷入 pending 段、注册
// 生效——回放与在线推送之间零缝隙零重叠，B3 订阅原子交付）。同连接重复订阅 =
// **替换**（sub.domains 整体换为新载荷集合——daemon-control-plane delta 3b 钉死，
// B4 澄清：非并集）；pending 回放段同样 = 覆盖（新回放段取代旧段，r3 低-2——
// 前端按 seq 幂等去重无损）。
//
//   - generation != 当前代际 → ErrCursorStale（前端全量重快照）；
//   - cursor 超前于当前序号 → ErrCursorFuture（bad_request）；
//   - cursor+1 早于环内最老 seq（游标过旧/环已被冲刷）→ ErrCursorStale；
//   - 域词表外 → ErrUnknownDomain（bad_request）；
//   - 回放 = 窗内 (cursor, 当前] 的订阅域事件，拷入 sub.pending（**不占订阅队列
//     ch**）；绑定层先写订阅确认 rsp、清门闩，再经 DrainPending 取走并先于在线
//     流写出（at-least-once 语义下重复/交叠无害，见文件头「投递次序说明」）。
//     窗内游标永远能回放——回放条数不受 subQueue 界（pending 是普通切片，长度
//     只受环窗 4096 界），不新增「回放超余量退 stale」触发条件。
//
// domains 为空数组 = 合法（订阅确认回显空集，不推任何域——前端可用它只取回放）。
// view = 前端订阅视图声明（D5：原文登记在订阅者上、viewDemand 聚合消费；空串/
// 未知格式保守忽略——不算需求也不报错；替换订阅时随 domains 一并整体替换）。
func (b *Bus) Subscribe(sub *Subscriber, domains []string, cursor *uint64, generation, view string) error {
	dm := make(map[string]bool, len(domains))
	for _, d := range domains {
		if !validDomains[d] {
			return fmt.Errorf("词表外订阅域 %q", d)
		}
		dm[d] = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if generation != "" && generation != b.gen {
		// 代际失配（spec「守护进程重启后旧游标失效」）：cursor_stale 引导全量
		// 重快照。缺省（不带 generation 的旧前端）退化为仅重放窗检查。
		return fmt.Errorf("%w: 代际失配（订阅带 %q，当前 %q）", ErrCursorStale, generation, b.gen)
	}
	var replay []Event
	if cursor != nil {
		if *cursor > b.seq {
			return fmt.Errorf("%w: %d > 当前 %d", ErrCursorFuture, *cursor, b.seq)
		}
		oldest := b.oldestSeqLocked()
		// 环空（尚无事件）时任何 cursor 都可从当前续播；环非空时要求 cursor+1
		// 不早于最老（否则窗内已缺段 = cursor_stale 引导重快照，MUST NOT 静默跳段）。
		if b.ringLen > 0 && *cursor+1 < oldest {
			return fmt.Errorf("%w: 游标 %d 早于重放窗起点 %d", ErrCursorStale, *cursor, oldest)
		}
		for i := 0; i < b.ringLen; i++ {
			ev := b.ring[(b.ringStart+i)%b.ringCap]
			if ev.Seq > *cursor && dm[ev.Domain] {
				replay = append(replay, ev)
			}
		}
	}
	sub.pending = replay
	sub.domains = dm
	sub.view = view
	b.subs[sub] = struct{}{}
	return nil
}

// viewDemand 某主机是否被任一在途订阅的 view 声明（D5 源③：订阅视图聚合到主机
// 集合）。退订/断连（订阅者从 b.subs 摘除）后贡献消失。
func (b *Bus) viewDemand(host [32]byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for sub := range b.subs {
		for _, id := range ParseView(sub.view) {
			if id == host {
				return true
			}
		}
	}
	return false
}

// DrainPending 原子取走 pending 回放段（换出为 nil）。调用方 = 绑定层 writer：
// 在订阅确认 rsp 写出且门闩清位后调用，取走后先于暂存缓冲/常规在线消费写出
// （「确认 → 回放 → 在线」三段次序的总线侧供给端）。锁内交换、锁外由调用方
// 写出——锁内只做切片换手，零阻塞。
func (s *Subscriber) DrainPending() []Event {
	s.bus.mu.Lock()
	p := s.pending
	s.pending = nil
	s.bus.mu.Unlock()
	return p
}

// Unsubscribe 摘订阅（幂等；未订阅/已摘均安全）。
func (b *Bus) Unsubscribe(sub *Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, sub)
}

// UnsubscribeDomains 从订阅中摘除若干域（幂等；未含域 = 无操作），摘空即整体
// 从总线摘除。**订阅域的增删只在 b.mu 内发生**（Subscribe 换集合、本函数删条目）
// ——publish 在同一把锁下经 matches 读 domains，锁外改这张 map 是运行时
// fatal 级竞态（concurrent map read and map write，recover 兜不住——exec-r1 H1：
// 此前 server 侧持 subMu 裸删，与 publish 的 b.mu 互不相干）。
func (b *Bus) UnsubscribeDomains(sub *Subscriber, domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range domains {
		delete(sub.domains, d)
	}
	if len(sub.domains) == 0 {
		delete(b.subs, sub)
	}
}

// terminateLocked 标记 overrun 并停投（publish 的投递失败路径调用）。
func (s *Subscriber) terminateOverrun() {
	s.once.Do(func() {
		s.overrun = true
		close(s.stop)
	})
}
