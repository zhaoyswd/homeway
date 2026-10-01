package control

// subscribe_b3_test.go — §2.2 B3 订阅原子交付的红绿用例（绑定层 wire 面）：
// 「确认帧 → 回放批 → 其后在线帧」三段次序（r3 低-1 扩三段断言）。
//
// 断言口径（对调度不确定边界鲁棒）：订阅请求发出后读到确认 rsp 之前出现的事件帧
// 必为回放内容的**重复**（at-least-once：其 seq 必在 rsp 之后再次出现——门闩前置
// 置位 ⇒ 注册后投递的在线事件被取到时门闩必已置位、复检暂存不写出；无门闩实现
// 会把只此一次的大 seq 在线事件写在线上，其 seq 不会再现 = 红）。rsp 之后的事件
// 帧按 seq 幂等去重覆盖全量无缺口。两路竞态形态（r1 高-1 / r2 新-1）：
//  ① 已订阅连接上的二次订阅（writer 已阻塞在 evC 的已武装 receive 形态——
//     3a exec-r1 [1401, 1..11] 同形态）；
//  ② 首次订阅，writer 在 Subscribe 返回与 reply 之间重入 step()——用 host.list
//     请求风暴保持 writer 活跃（非阻塞 evC 分支在注册后即 armed）。
// 每路循环多轮压竞态窗口；变异自证（临时去掉 takeEvent 的门闩复检 → 本组红）
// 记录在 exec-report。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

// b3RawDial 原始连接 + 握手（字节级帧序断言用）。
func b3RawDial(t *testing.T, ts *testServer) (net.Conn, *bufio.Reader) {
	t.Helper()
	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	hello := `{"protoVersion":1,"frontend":{"kind":"raw","name":"b3","version":"0"}}`
	if _, err := nc.Write(EncodeFrame(OpHello, []byte(hello))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(nc)
	readFrameRaw(t, r) // welcome
	return nc, r
}

// b3Pub 发布一条 session 事件（返回 seq）。
func b3Pub(t *testing.T, ts *testServer, i int) {
	t.Helper()
	if _, err := ts.bus.Publish(facade.DomainSession, facade.KindSessionStateChanged,
		facade.SessionStateChangedPayload{Host: "b3", State: fmt.Sprintf("s%d", i)}); err != nil {
		t.Fatal(err)
	}
}

// b3Frame 一条读到的帧（rsp 或 evt）。
type b3Frame struct {
	op   byte
	corr uint64
	ok   bool
	seq  uint64
}

// b3ReadUntil 读帧直到「目标确认 rsp 已见 + 其后事件幂等去重覆盖 1..total」
// （带时限；goodbye = 直接失败；其它 corr 的 rsp〔host.list 风暴等〕忽略）。
func b3ReadUntil(t *testing.T, nc net.Conn, r *bufio.Reader, wantCorr uint64, total int) (rsp b3Frame, preRspSeqs, postRspSeqs []uint64) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	gotRsp := false
	for {
		if gotRsp && rsp.corr == wantCorr && coverComplete(postRspSeqs, total) {
			return
		}
		// 单帧读超时：事件停摆（门闩卡死/变异形态）时干净失败而非挂起（readFrameRaw
		// 的阻塞读不受上面的 deadline select 管）。
		_ = nc.SetReadDeadline(time.Now().Add(3 * time.Second))
		select {
		case <-deadline:
			t.Fatalf("读帧超时（gotRsp=%v corr=%d want=%d pre=%d post=%d/%d）", gotRsp, rsp.corr, wantCorr, len(preRspSeqs), len(postRspSeqs), total)
		default:
		}
		op, body := readFrameRaw(t, r)
		switch op {
		case OpRsp:
			var rspB ResponseBody
			if err := json.Unmarshal(body, &rspB); err != nil {
				t.Fatalf("rsp JSON：%v", err)
			}
			if rspB.Corr != wantCorr {
				continue // 风暴 rsp（host.list 等）：忽略
			}
			rsp, gotRsp = b3Frame{op: op, corr: rspB.Corr, ok: rspB.Ok}, true
		case OpEvt:
			var ev EventBody
			if err := json.Unmarshal(body, &ev); err != nil {
				t.Fatalf("evt JSON：%v", err)
			}
			if gotRsp {
				postRspSeqs = append(postRspSeqs, ev.Seq)
			} else {
				preRspSeqs = append(preRspSeqs, ev.Seq)
			}
		case OpGoodbye:
			var g GoodbyeBody
			_ = json.Unmarshal(body, &g)
			t.Fatalf("不应断连：goodbye(%s)", g.Reason)
		default:
			continue
		}
	}
}

// coverComplete post-rsp 的 seq 去重后是否已覆盖 1..total。
func coverComplete(seqs []uint64, total int) bool {
	seen := make(map[uint64]bool, len(seqs))
	for _, s := range seqs {
		seen[s] = true
	}
	for want := uint64(1); want <= uint64(total); want++ {
		if !seen[want] {
			return false
		}
	}
	return true
}

// b3Assert 三段断言：确认帧存在且 corr 匹配；确认帧之前的 evt 必为重复（seq 在
// rsp 之后再现——无门闩实现会漏出只出现一次的大 seq 在线事件）；rsp 之后幂等
// 去重覆盖 1..total 无缺口。
func b3Assert(t *testing.T, corr uint64, rsp b3Frame, preRspSeqs, postRspSeqs []uint64, total int) {
	t.Helper()
	if rsp.corr != corr || !rsp.ok {
		t.Fatalf("订阅确认 rsp 异常：corr=%d ok=%v（期望 corr=%d）", rsp.corr, rsp.ok, corr)
	}
	post := make(map[uint64]bool, len(postRspSeqs))
	for _, s := range postRspSeqs {
		post[s] = true
	}
	for _, s := range preRspSeqs {
		if !post[s] {
			t.Fatalf("三段次序破坏：确认帧前出现 seq=%d 且未在其后再现——注册后投递的在线事件越过确认/回放先行写出（门闩复检缺失形态）", s)
		}
	}
	if !coverComplete(postRspSeqs, total) {
		t.Fatalf("rsp 之后事件不完整：去重后应覆盖 1..%d（实得 %d 帧）", total, len(postRspSeqs))
	}
}

// TestServerB3SecondSubscribeArmedReceive 竞态①：已订阅连接上的二次订阅。
func TestServerB3SecondSubscribeArmedReceive(t *testing.T) {
	const iters = 30
	for it := 0; it < iters; it++ {
		ts := startTestServer(t, facade.BusConfig{})
		nc, r := b3RawDial(t, ts)
		// 预发布 1..5；首次订阅（corr=1，cursor=0）收齐回放——writer 此后停在
		// 阻塞 select（evC 已武装）。
		for i := 1; i <= 5; i++ {
			b3Pub(t, ts, i)
		}
		if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":1,"op":"events.subscribe","args":{"domains":["session"],"cursor":0,"generation":"%s"}}`, ts.bus.Generation())))); err != nil {
			t.Fatal(err)
		}
		rsp, pre, post := b3ReadUntil(t, nc, r, 1, 5)
		b3Assert(t, 1, rsp, pre, post, 5)
		b3Pub(t, ts, 6) // 在线事件 6：writer 取出写出后重新驻留 select
		// —— 竞态窗：二次订阅（corr=2，cursor=0）× 定步并发发布 7..46（150µs/条
		// ——背靠背发完赶在订阅窗之前，命中不了 [注册, rsp 写出] 窗口）。
		go func() {
			for i := 7; i <= 46; i++ {
				b3Pub(t, ts, i)
				time.Sleep(150 * time.Microsecond)
			}
		}()
		if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":2,"op":"events.subscribe","args":{"domains":["session"],"cursor":0,"generation":"%s"}}`, ts.bus.Generation())))); err != nil {
			t.Fatal(err)
		}
		rsp2, pre2, post2 := b3ReadUntil(t, nc, r, 2, 46)
		b3Assert(t, 2, rsp2, pre2, post2, 46)
	}
}

// TestServerB3FirstSubscribeActiveWriter 竞态②：首次订阅，writer 在 Subscribe
// 返回与 reply 之间重入 step()——host.list 风暴保持 writer 活跃（非阻塞 evC 分支
// 在注册后即 armed，无门闩会先吐在线事件）。
func TestServerB3FirstSubscribeActiveWriter(t *testing.T) {
	const iters = 30
	for it := 0; it < iters; it++ {
		ts := startTestServer(t, facade.BusConfig{})
		nc, r := b3RawDial(t, ts)
		for i := 1; i <= 5; i++ {
			b3Pub(t, ts, i)
		}
		// 并发发布 6..45（注册后投递 = 在线事件）。发布走总线、不碰 nc——nc 的写
		// 全部留在主 goroutine（并发写同一 socket 会交错坏帧）。
		pubDone := make(chan struct{})
		go func() {
			defer close(pubDone)
			for i := 6; i <= 45; i++ {
				b3Pub(t, ts, i)
				time.Sleep(150 * time.Microsecond)
			}
		}()
		// 订阅请求先行、host.list 风暴紧随其后（同一 goroutine 顺序写）：reader
		// 逐帧分发，opSubscribe goroutine 与风暴应答交错——writer 持续有 highC
		// 可排（循环重入 step，非阻塞 evC 分支在注册后即 armed）。
		if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":1,"op":"events.subscribe","args":{"domains":["session"],"cursor":0,"generation":"%s"}}`, ts.bus.Generation())))); err != nil {
			t.Fatal(err)
		}
		for c := 1000; c < 1030; c++ {
			if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":%d,"op":"host.list"}`, c)))); err != nil {
				t.Fatal(err)
			}
		}
		rsp, pre, post := b3ReadUntil(t, nc, r, 1, 45)
		b3Assert(t, 1, rsp, pre, post, 45)
		<-pubDone
	}
}

// TestServerB3LargeReplayCompleteDelivery §2.2③（wire 面）：回放 600 条
// （> 默认订阅队列 512）经真实连接完整送达（非 stale），其后在线事件续接。
func TestServerB3LargeReplayCompleteDelivery(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	for i := 1; i <= 600; i++ {
		b3Pub(t, ts, i)
	}
	nc, r := b3RawDial(t, ts)
	if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":7,"op":"events.subscribe","args":{"domains":["session"],"cursor":0,"generation":"%s"}}`, ts.bus.Generation())))); err != nil {
		t.Fatal(err)
	}
	rsp, pre, post := b3ReadUntil(t, nc, r, 7, 600)
	b3Assert(t, 7, rsp, pre, post, 600)
	if len(pre) != 0 {
		t.Fatalf("600 条回放全部应在确认帧之后落线，确认前出现 %d 条", len(pre))
	}
	// 在线续接：读 3 条在线事件（恰 seq 601..603）。
	go func() {
		for i := 601; i <= 603; i++ {
			b3Pub(t, ts, i)
		}
	}()
	deadline := time.After(10 * time.Second)
	tail := make(map[uint64]bool, 3)
	for len(tail) < 3 {
		select {
		case <-deadline:
			t.Fatalf("大回放后在线续接不足：%d/3", len(tail))
		default:
		}
		_ = nc.SetReadDeadline(time.Now().Add(3 * time.Second))
		op, body := readFrameRaw(t, r)
		switch op {
		case OpEvt:
			var ev EventBody
			if err := json.Unmarshal(body, &ev); err != nil {
				t.Fatalf("evt JSON：%v", err)
			}
			tail[ev.Seq] = true
		case OpGoodbye:
			var g GoodbyeBody
			_ = json.Unmarshal(body, &g)
			t.Fatalf("不应断连：goodbye(%s)", g.Reason)
		}
	}
	for want := uint64(601); want <= 603; want++ {
		if !tail[want] {
			t.Fatalf("在线续接缺 seq=%d", want)
		}
	}
}

// TestServerB3ErrorConfirmClearsLatch 错误应答清位（r2 新-1 配套）：cursor_stale
// 的订阅错误 rsp 之后 writer 恢复常规消费——错误确认后的在线事件全部送达、连接
// 不断（门闩卡死形态 = 事件永不落线，本测试以「全量送达 + 无 goodbye」区分）。
func TestServerB3ErrorConfirmClearsLatch(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{SubQueue: 256})
	nc, r := b3RawDial(t, ts)
	// 先订阅成功（corr=1）——连接成为已订阅形态（writer 驻留 evC 消费）。
	if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":1,"op":"events.subscribe","args":{"domains":["session"],"generation":"%s"}}`, ts.bus.Generation())))); err != nil {
		t.Fatal(err)
	}
	rsp, pre, post := b3ReadUntil(t, nc, r, 1, 0)
	b3Assert(t, 1, rsp, pre, post, 0)
	// 代际失配的二次订阅（corr=2）→ 错误 rsp cursor_stale；紧随其后发布 100 条
	//（订阅队列 64——若错误 rsp 不清位、writer 停止消费，事件停摆/断连；清位
	// 则全量送达且连接存活）。
	go func() {
		for i := 1; i <= 100; i++ {
			b3Pub(t, ts, i)
		}
	}()
	if _, err := nc.Write(EncodeFrame(OpReq, []byte(`{"corr":2,"op":"events.subscribe","args":{"domains":["session"],"generation":"gen-other"}}`))); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	var gotErrRsp bool
	evs := make(map[uint64]bool, 100)
	for !gotErrRsp || len(evs) < 100 {
		select {
		case <-deadline:
			t.Fatalf("错误确认清位失败：gotErrRsp=%v evs=%d/100（门闩卡死 = 事件停摆）", gotErrRsp, len(evs))
		default:
		}
		_ = nc.SetReadDeadline(time.Now().Add(3 * time.Second))
		op, body := readFrameRaw(t, r)
		switch op {
		case OpRsp:
			var b ResponseBody
			_ = json.Unmarshal(body, &b)
			if b.Corr == 2 {
				if b.Ok {
					t.Fatal("代际失配订阅应错误应答")
				}
				if b.Error != facade.CodeCursorStale {
					t.Fatalf("错误码应为 cursor_stale，得到 %q", b.Error)
				}
				gotErrRsp = true
			}
		case OpEvt:
			var ev EventBody
			if err := json.Unmarshal(body, &ev); err != nil {
				t.Fatalf("evt JSON：%v", err)
			}
			evs[ev.Seq] = true
		case OpGoodbye:
			var g GoodbyeBody
			_ = json.Unmarshal(body, &g)
			t.Fatalf("连接被 goodbye(%s) 断开——错误确认后订阅队列应恢复消费", g.Reason)
		}
	}
	for want := uint64(1); want <= 100; want++ {
		if !evs[want] {
			t.Fatalf("事件 seq=%d 未送达（错误确认清位后应恢复常规消费）", want)
		}
	}
}

// TestServerB3ConfirmBeforeReplayHeldFramesOrder 清位补写次序（r3 低-1 三段：
// 确认 → 回放批 → 其后在线帧——门闩期暂存在线事件在回放段之后）。
func TestServerB3ConfirmBeforeReplayHeldFramesOrder(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	for i := 1; i <= 10; i++ {
		b3Pub(t, ts, i)
	}
	nc, r := b3RawDial(t, ts)
	// 并发发布紧随订阅（在线事件必在门闩期被取出暂存）。
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 11; i <= 20; i++ {
			b3Pub(t, ts, i)
		}
	}()
	if _, err := nc.Write(EncodeFrame(OpReq, []byte(fmt.Sprintf(`{"corr":3,"op":"events.subscribe","args":{"domains":["session"],"cursor":0,"generation":"%s"}}`, ts.bus.Generation())))); err != nil {
		t.Fatal(err)
	}
	rsp, pre, post := b3ReadUntil(t, nc, r, 3, 20)
	b3Assert(t, 3, rsp, pre, post, 20)
	wg.Wait()
	// 段序细化：post 序列里，全部 ≤ rsp 边界前的回放 seq 必须整体先于任何 > 边界
	// 的在线 seq——即存在切分点 k：post[0..k) 的 seq 均 ≤ 10（回放），post[k..) 均
	// > 10 之外不允许再出现 ≤ 10 的回放 seq（回放批整体先行）。
	seenOnline := false
	for _, s := range post {
		if s > 10 {
			seenOnline = true
			continue
		}
		if seenOnline && s <= 10 {
			t.Fatalf("回放批未整体先行：在线 seq 之后又出现回放 seq=%d", s)
		}
	}
	_ = io.Discard
}
