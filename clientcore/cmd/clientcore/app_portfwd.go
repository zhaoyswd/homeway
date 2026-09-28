//go:build cshared

// App 专用：端口转发监听器（CLI 不编）。
// app_portfwd.go — 把「出口可达目标的 TCP 端口」映射到手机的 127.0.0.1 固定端口：
// 浏览器等任意应用访问 127.0.0.1:<listen>，核在这里 accept，经隧道客户端拨出目标后
// pipeBoth 双向转发。回环流量不进 TUN（也不受路由/绕过名单影响），所以这条路径与
// gVisor 数据面并行存在。
//
// 目标语义（ArkTS 侧 PortForward 的镜像，见 model/PortForwardRules.ets）：
//
//	TargetIp == ""  → DialTCPPort：拨**出口主机自己**的端口。出口侧 OnTCP 在 exit-node
//	                  模式下拨 localhost:port（上游行为）——Docker --network host 部署下
//	                  即宿主机端口，官方 v0.6.0 出口同样支持。
//	TargetIp 为 IP  → DialTCP：经出口 OnTCPForward 拨任意可达目标（出口侧视角解析路由）。
//
// 生命周期挂 tunRun 世代：attached 时 setPortForwards 首启，运行中可经
// ClientCoreTunSetPortForwards 整表热替换（不重连隧道），runTun2Tailcat 收工时
// stopPortForwards（先关监听器，再由世代收尾关客户端，残留转发连接随之断掉）。
// 单条监听失败只记状态、不阻断隧道（与「软失败不回滚」的两阶段启动哲学一致）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"C"
)

// tunPortForward 是 tunConfig.PortForwards 的一条。
// 字段名与扩展侧拼 JSON 的键一致（listen / targetIp / targetPort）。
type tunPortForward struct {
	Listen     uint16 `json:"listen"`
	TargetIp   string `json:"targetIp"` // 空 = 出口主机自己
	TargetPort uint16 `json:"targetPort"`
}

// pfTargetText 展示用目标文本（与 ArkTS 侧 forwardTargetText 同语义）。
func pfTargetText(f tunPortForward) string {
	if f.TargetIp == "" {
		return fmt.Sprintf("主机:%d", f.TargetPort)
	}
	return netip.AddrPortFrom(netip.MustParseAddr(f.TargetIp), f.TargetPort).String()
}

// pfState 一条映射的运行状态（tunStatusJSON 下发给扩展，端口转发页展示）。
// conns 是当前活跃转发连接数（accept 成功 +1、连接结束 -1）。
type pfState struct {
	Listen uint16
	Target string
	State  string // listening | failed
	Err    string
	conns  atomic.Int64
}

// setPortForwards 把本世代的端口转发**整体重置**为 fwds 这张表：停掉旧监听器、
// 按新表逐条起 127.0.0.1 监听器。三个消费方共用这一条路——
//   - attach 时首启（tunmode 的 tunRun，pfLn 为空的特例）；
//   - 运行中改映射（ClientCoreTunSetPortForwards，热生效，不重连隧道）；
//   - 世代收工（stopPortForwards = setPortForwards(nil)）。
//
// 整个重置持 pfMu：与 pfStatusJSON（状态查询）互斥，重配期间查询要么看到全旧、
// 要么看到全新，不会读到半张表。已建立的转发连接不强关：关闭 listener 不影响
// 已 accept 的连接，远端一断 pipeBoth 自然收口。
func (t *tunRunner) setPortForwards(fwds []tunPortForward) {
	t.pfMu.Lock()
	defer t.pfMu.Unlock()
	lns := t.pfLn
	t.pfLn = nil
	t.pfStates = nil
	for _, ln := range lns {
		_ = ln.Close()
	}
	if len(lns) > 0 {
		t.logf("port-forward: 已停止全部监听器（%d 个）", len(lns))
	}
	if len(fwds) > 0 {
		t.pfStates = make([]*pfState, 0, len(fwds))
	}
	for _, f := range fwds {
		st := &pfState{Listen: f.Listen, Target: pfTargetText(f), State: "listening"}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", f.Listen))
		if err != nil {
			st.State = "failed"
			st.Err = err.Error()
			t.logf("port-forward: 监听 127.0.0.1:%d 失败（%v）——该条映射不可用，不影响隧道", f.Listen, err)
		} else {
			t.logf("port-forward: 127.0.0.1:%d -> %s 监听中", f.Listen, st.Target)
			t.pfLn = append(t.pfLn, ln)
			go t.pfAccept(ln, f, st)
		}
		t.pfStates = append(t.pfStates, st)
	}
}

// stopPortForwards 世代收工：关掉全部监听器（accept goroutine 随 Accept 报错退出），
// 并清空状态——停止之后它们确实不在监听，状态里不许残留 "listening"。
func (t *tunRunner) stopPortForwards() {
	t.setPortForwards(nil)
}

// tunSetPortForwardsJSON 是 ClientCoreTunSetPortForwards 的实现：把新映射表热应用到
// 当前世代（不重连隧道）。入参 JSON 形如 {"portForwards":[{listen,targetIp,targetPort}]}，
// 与 tunConfig 的同名字段同一形状（扩展侧拼装逻辑只有一份）。
// 返回 0 = 已应用；-1 = 当前没有**已接管数据面**的世代（改动会随下次连接的 tunConfig
// 自然生效，调用方可稍后重试）；-2 = JSON 非法。
//
// ⚠️ 判据必须是「已 attached 且世代还活着」（review 复审：此前只看 currentTunRun()
// 是否为 nil，而 **tunNow 从不置空**——世代收工后它仍指着那个 run、runner 也还在，
// 于是热更新会把监听器装进一个已经跑过 stopPortForwards 的死世代：返回 0 谎报成功、
// 端口被永久占住（后续同端口映射恒 EADDRINUSE）、状态面还显示"监听中"）。
// 这里与 attachTun / runRecoverAt / tunStopWait 用同一套闸：
//   - probeRunning==0：没有在世代的核（已收工/从未启动）——正是那些窄窗口；
//   - stage != attached：prepare 期（核在暖机、还没接 fd）不接受热更新，
//     改动由本次 attach 的 tunConfig 整表生效。
func tunSetPortForwardsJSON(cfg string) int {
	var v struct {
		PortForwards []tunPortForward `json:"portForwards"`
	}
	if err := json.Unmarshal([]byte(cfg), &v); err != nil {
		return -2
	}
	seen := make(map[uint16]struct{}, len(v.PortForwards))
	for _, f := range v.PortForwards {
		if f.Listen == 0 || f.TargetPort == 0 {
			return -2
		}
		if _, dup := seen[f.Listen]; dup {
			// 同表内重复监听端口：第二条注定 EADDRINUSE，界面会显示一条莫名其妙的
			// "失败"（表单本来拦得住，这里兜住被绕过/损坏的 JSON）。
			return -2
		}
		seen[f.Listen] = struct{}{}
	}
	r := currentTunRun()
	if r == nil || probeRunning.Load() == 0 {
		return -1
	}
	if st, _, _, _ := tunStageSnapshot(); st != stageAttached {
		return -1
	}
	select {
	case <-r.done: // 世代正在收工/已收工
		return -1
	default:
	}
	tr := r.runner()
	if tr == nil {
		return -1
	}
	tr.setPortForwards(v.PortForwards)
	// 应用期间世代可能换代或收工（stopPortForwards 先拿到 pfMu、我们后起监听器）——
	// 复查一次，两件事任一发生就把刚起的监听器随手收掉，绝不给死世代留孤儿。
	stale := false
	if currentTunRun() != r {
		stale = true
	}
	select {
	case <-r.done:
		stale = true
	default:
	}
	if stale {
		tr.stopPortForwards()
		return -1
	}
	return 0
}

// ClientCoreTunSetPortForwards 运行中更新端口映射表（热生效）：App 侧保存/删除映射后
// 经状态通道的 pfSet 命令到这里，不再要求「断开重连」。见 app_portfwd.go 头注释。
//
//export ClientCoreTunSetPortForwards
func ClientCoreTunSetPortForwards(cCfg *C.char) C.int {
	return C.int(tunSetPortForwardsJSON(C.GoString(cCfg)))
}

// pfAccept 一条映射的 accept 循环：每条入站连接拨一次隧道、双向泵。
func (t *tunRunner) pfAccept(ln net.Listener, f tunPortForward, st *pfState) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.logf("port-forward: accept %d: %v", f.Listen, err)
			}
			return
		}
		// 与 gVisor 流共用并发流保险阀：防失控应用把内存/goroutine 打满（S22 同款理由）
		if n := t.st.tcpFlows.Add(1); n > maxTCPFlows {
			t.st.tcpFlows.Add(-1)
			if r := t.st.flowRejected.Add(1); r <= 5 || r%50 == 0 {
				t.logf("port-forward %d: 并发流已达上限 %d，拒绝（累计拒绝 %d）", f.Listen, maxTCPFlows, r)
			}
			_ = c.Close()
			continue
		}
		st.conns.Add(1)
		t.st.pfAccepted.Add(1)
		go func(c net.Conn) {
			defer t.st.tcpFlows.Add(-1)
			defer st.conns.Add(-1)
			ctx, cancel := context.WithTimeout(context.Background(), t.dialTimeout)
			remote, err := t.pfDial(ctx, f)
			cancel()
			if err != nil {
				t.st.pfFails.Add(1)
				if n := t.st.pfFails.Load(); n <= 5 || n%20 == 0 {
					t.logf("port-forward: %d -> %s 拨号失败 #%d: %v", f.Listen, st.Target, n, err)
				}
				// 本地握手已完成、上游不可达：用 RST 收口（SO_LINGER 0），别用优雅 FIN——
				// 应用会把「连接建立后立刻 EOF」当成响应结束而静默挂住（与 acceptTCP 同一教训）。
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				_ = c.Close()
				return
			}
			pipeBoth(t.logf, c, remote)
		}(c)
	}
}

// pfDial 按目标形态选库 API：空 = 出口自己（DialTCPPort），IP = 经出口拨任意目标（DialTCP）。
func (t *tunRunner) pfDial(ctx context.Context, f tunPortForward) (net.Conn, error) {
	if f.TargetIp == "" {
		return t.cl.DialTCPPort(ctx, f.TargetPort)
	}
	ip, err := netip.ParseAddr(f.TargetIp)
	if err != nil || !ip.Is4() {
		// 配置侧已校验只收 IPv4 字面量；走到这里说明 JSON 被绕过/损坏，按配置错误报
		return nil, fmt.Errorf("目标地址非法：%q", f.TargetIp)
	}
	return t.cl.DialTCP(ctx, netip.AddrPortFrom(ip, f.TargetPort))
}

// pfStatusJSON 给 tunStatusJSON 用：按配置顺序输出每条映射的状态。
func (t *tunRunner) pfStatusJSON() []map[string]any {
	t.pfMu.Lock()
	defer t.pfMu.Unlock()
	out := make([]map[string]any, 0, len(t.pfStates))
	for _, st := range t.pfStates {
		out = append(out, map[string]any{
			"listen": st.Listen,
			"target": st.Target,
			"state":  st.State,
			"err":    st.Err,
			"conns":  st.conns.Load(),
		})
	}
	return out
}
