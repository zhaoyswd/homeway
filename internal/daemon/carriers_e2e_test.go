package daemon

// carriers_e2e_test.go — 承载面端到端（3e §3.5）：真实 daemon（startDaemonForTest =
// 真 facade 主机表 + 真 Carriers〔Attach 接线〕+ 真控制面 UDS 全链）驱动
// forward 规则增删查 / socks 开关查 / speedtest 轮流与取消——批 1 的承载管理器
// 真实现经控制面全链（非桩）。不依赖真实后端：会话对假端点的拨号失败属预期
// （forward 上游 RST 收口 / speedtest link_down 等待相位）。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
)

// freeTCPPort 抓一个空闲回环端口（听完即关——存在与并发达抢的窗口，测试串行下可用）。
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// e2eAddHost 经控制面 host.add 登记一台主机（假探测 direct 档），返回 hex id。
func e2eAddHost(t *testing.T, sock, name string, peer byte) string {
	t.Helper()
	tok := hostTok(t, peer, name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "e2e", Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Name: name, Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	var res control.HostAddResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	return res.ID
}

func TestCarriersE2EForwardAndSocks(t *testing.T) {
	_, sock := startDaemonForTest(t, fakeProbeDirect)
	ali := e2eAddHost(t, sock, "ali", 0x21)
	_ = ali // 对账面（list 应显示该主机名下规则）

	// forward add：真监听器起来（回环可连）。
	port := freeTCPPort(t)
	var out bytes.Buffer
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", fmt.Sprint(port), "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已建转发") {
		t.Fatalf("add 输出：%s", out.String())
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("监听未起：%v", err)
	}
	_ = conn.Close() // 上游拨号对假端点失败属预期（RST/快速收口）

	// 同端口再 add（含跨 socks）→ bad_request 语义（真管理器全局唯一）。
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", fmt.Sprint(port), "--state", stateDirOf(sock)}, "t", &out); err == nil || !strings.Contains(err.Error(), "已被") {
		t.Fatalf("全局端口冲突应可区分：%v", err)
	}

	// forward list --json：listening 态 + 字段。
	out.Reset()
	if err := forwardCLI([]string{"list", "--json", "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) != 1 || arr[0]["state"] != "listening" || arr[0]["listen"] != float64(port) {
		t.Fatalf("list：%s", out.String())
	}

	// socks on（换端口避开被测端口）：真 SOCKS5 监听。
	sport := freeTCPPort(t)
	out.Reset()
	if err := socksCLI([]string{"on", "--host", "ali", "--listen", fmt.Sprint(sport), "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	sconn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sport), 2*time.Second)
	if err != nil {
		t.Fatalf("socks 监听未起：%v", err)
	}
	// SOCKS5 no-auth 协商一发即答（method 00 应答 = 真服务端在听）。
	_, _ = sconn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	_ = sconn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := sconn.Read(buf); err != nil || buf[0] != 0x05 || buf[1] != 0x00 {
		t.Fatalf("SOCKS5 no-auth 协商异常：%v %x", err, buf)
	}
	_ = sconn.Close()

	// socks off：监听收口（连接拒绝）+ 端口记忆保留（status --json 暴露）。
	out.Reset()
	if err := socksCLI([]string{"off", "--host", "ali", "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sport), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("off 后监听应关闭")
	}
	out.Reset()
	if err := socksCLI([]string{"status", "--json", "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	var sarr []map[string]any
	if err := json.Unmarshal(out.Bytes(), &sarr); err != nil {
		t.Fatal(err)
	}
	if len(sarr) != 1 || sarr[0]["on"] != false || sarr[0]["listen"] != float64(sport) {
		t.Fatalf("off 后记忆端口应可见：%s", out.String())
	}

	// forward delete：监听关闭、在世连接不强关口径文案。
	out.Reset()
	if err := forwardCLI([]string{"delete", "--host", "ali", "--listen", fmt.Sprint(port), "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		_ = c.Close()
		t.Fatal("delete 后监听应关闭")
	}

	// EADDRINUSE（守护外占用）：测试进程占住端口 → daemon 真监听失败 → bad_request
	// 文案含占用原因、规则不入表。
	occ, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer occ.Close()
	held := uint16(occ.Addr().(*net.TCPAddr).Port)
	out.Reset()
	err = forwardCLI([]string{"add", "--host", "ali", "--listen", fmt.Sprint(held), "--state", stateDirOf(sock)}, "t", &out)
	if err == nil || !strings.Contains(err.Error(), "守护进程外的本机进程占用") || !strings.Contains(err.Error(), "规则未入表") {
		t.Fatalf("EADDRINUSE 文案（含占用原因、不入表）：%v", err)
	}
	out.Reset()
	if err := forwardCLI([]string{"list", "--json", "--state", stateDirOf(sock)}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), fmt.Sprintf(`"listen":%d`, held)) {
		t.Fatalf("失败规则不得入表：%s", out.String())
	}
}

// TestCarriersE2EHostRemoveCascade 主机删除级联（真 RemoveHost → Carriers 级联）。
func TestCarriersE2EHostRemoveCascade(t *testing.T) {
	_, sock := startDaemonForTest(t, fakeProbeDirect)
	ali := e2eAddHost(t, sock, "ali", 0x22)
	dir := stateDirOf(sock)
	port := freeTCPPort(t)
	sport := freeTCPPort(t)

	var out bytes.Buffer
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", fmt.Sprint(port), "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if err := socksCLI([]string{"on", "--host", "ali", "--listen", fmt.Sprint(sport), "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}

	// host.remove（控制面）→ forward 规则与 socks 记忆级联消失。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "e2e", Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Request(ctx, facade.OpHostRemove, control.HostRemoveArgs{Host: ali}); err != nil {
		t.Fatal(err)
	}
	c.Close()

	out.Reset()
	if err := forwardCLI([]string{"list", "--json", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), fmt.Sprintf(`"listen":%d`, port)) {
		t.Fatalf("级联后 forward 规则应消失：%s", out.String())
	}
	out.Reset()
	if err := socksCLI([]string{"status", "--json", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	var sarr []map[string]any
	_ = json.Unmarshal(out.Bytes(), &sarr)
	if len(sarr) != 0 {
		t.Fatalf("级联后 socks 记忆应消失：%s", out.String())
	}
}

// TestCarriersE2ESocksPortRangeServerSide 守护侧值域闸（真 SocksManager：1024–65535
// 与 forward 同一条——变异自证 b 的红路载体）。
func TestCarriersE2ESocksPortRangeServerSide(t *testing.T) {
	_, sock := startDaemonForTest(t, fakeProbeDirect)
	ali := e2eAddHost(t, sock, "ali", 0x23)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "e2e", Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Request(ctx, facade.OpSocksOn, control.SocksOnArgs{Host: ali, Listen: 80}); err == nil || string(err.(control.CodeError)) != facade.CodeBadRequest {
		t.Fatalf("端口 80 应被守护侧值域闸拒（bad_request）：%v", err)
	}
}

// TestCarriersE2ESpeedtestWaitingAndCancel speedtest 经控制面全链：start 立即
// waiting（waitMs 预算交 runner 状态机）、cancel 打断等待期 → cancelled 终态可轮询。
func TestCarriersE2ESpeedtestWaitingAndCancel(t *testing.T) {
	_, sock := startDaemonForTest(t, fakeProbeDirect)
	ali := e2eAddHost(t, sock, "ali", 0x24)

	ctx := context.Background()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "e2e", Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// start：立即返回 waiting（链路未就绪的等待由 runner 承载，不占请求）。
	raw, err := c.Request(ctx, facade.OpSpeedtestStart, control.SpeedtestStartArgs{Host: ali, WaitMs: 60000})
	if err != nil {
		t.Fatal(err)
	}
	var ack control.SpeedtestStartAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Phase != "waiting" {
		t.Fatalf("start 应立即返回 waiting：%+v", ack)
	}

	// status：waiting 相位（等待窗内；对假端点的拨号失败 → link_down 重试窗）。
	waited := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := c.Request(ctx, facade.OpSpeedtestStatus, control.SpeedtestStatusArgs{Host: ali})
		if err != nil {
			t.Fatal(err)
		}
		var st control.SpeedtestStatusResult
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		if st.Waiting {
			waited = true
			break
		}
		if st.Result != nil {
			t.Fatalf("等待预算内不应出终态：%+v", st.Result)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !waited {
		t.Fatal("5s 内未见 waiting 相位")
	}

	// cancel：打断等待期 → cancelled 终态（Result 携带，CLI 轮询可收）。
	if _, err := c.Request(ctx, facade.OpSpeedtestCancel, control.SpeedtestCancelArgs{Host: ali}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := c.Request(ctx, facade.OpSpeedtestStatus, control.SpeedtestStatusArgs{Host: ali})
		if err != nil {
			t.Fatal(err)
		}
		var st control.SpeedtestStatusResult
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		if st.Result != nil {
			if st.Result.Reason != "cancelled" {
				t.Fatalf("cancel 后终态应为 cancelled：%+v", st.Result)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("cancel 后 5s 内未见终态（取消未打断等待期）")
}

// stateDirOf 从 sock 路径还原 state 目录（CLI --state 参数用）。
func stateDirOf(sock string) string {
	return strings.TrimSuffix(sock, "/"+control.ControlSockName)
}
