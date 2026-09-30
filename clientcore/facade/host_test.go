package facade

// host_test.go — Host.DialPort 三态（任务 3.3 验证）：正常 / 重建窗口
// （ErrSessionNotCurrent 的 facade 哨兵）/ 会话不在（表外 Host=nil 与登记在册
// 会话对象不在=ErrNoHost 两路）。假会话经 dialPort 注入缝（生产 = Session.
// DialPort）。

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// injectDialPort 覆写 dialPort 注入缝，返回还原函数。
func injectDialPort(fn func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error)) func() {
	orig := dialPort
	dialPort = fn
	return func() { dialPort = orig }
}

// TestHostDialPortNormal 正常态：拨号透传到会话（端口原样）。
func TestHostDialPortNormal(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	restore := injectDialPort(func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error) {
		if port != 7724 {
			t.Errorf("端口应原样透传，实得 %d", port)
		}
		return c1, nil
	})
	defer restore()

	h := &Host{rec: HostRecord{ID: "aa"}, sess: &hostsession.Session{}}
	got, err := h.DialPort(context.Background(), 7724)
	if err != nil {
		t.Fatal(err)
	}
	if got != c1 {
		t.Fatal("应返回会话拨号产物")
	}
}

// TestHostDialPortRebuildWindow 重建窗口：会话返回 hostsession.ErrSessionNotCurrent
// → 映射 facade 哨兵（绑定层据此走 no_session 族）。
func TestHostDialPortRebuildWindow(t *testing.T) {
	restore := injectDialPort(func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error) {
		return nil, hostsession.ErrSessionNotCurrent
	})
	defer restore()

	h := &Host{rec: HostRecord{ID: "aa"}, sess: &hostsession.Session{}}
	_, err := h.DialPort(context.Background(), 7724)
	if !errors.Is(err, ErrSessionNotCurrent) {
		t.Fatalf("重建窗口应 ErrSessionNotCurrent（facade 哨兵），实得 %v", err)
	}
}

// TestHostDialPortNoSession 会话不在两路：表外 = Daemon.Host 返回 nil（绑定点
// no_host 族）；登记在册但会话对象不在（构造期失败）= ErrNoHost（沿寻址面不可达
// 族——保持既有 wire 行为）。
func TestHostDialPortNoSession(t *testing.T) {
	dir := t.TempDir()
	d := newTestDaemon(t)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	// 表外：Host = nil。
	if h := d.Host([32]byte{63}); h != nil {
		t.Fatalf("表外 Host 应 nil，实得 %+v", h)
	}
	// 登记在册但会话对象不在：dialPort 缝不应被触达。
	called := false
	restore := injectDialPort(func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error) {
		called = true
		return nil, nil
	})
	defer restore()
	h := &Host{rec: HostRecord{ID: "aa"}}
	if _, err := h.DialPort(context.Background(), 7724); !errors.Is(err, ErrNoHost) {
		t.Fatalf("会话对象不在应 ErrNoHost，实得 %v", err)
	}
	if called {
		t.Fatal("会话对象不在时不得触达拨号缝")
	}
}

// TestHostSnapshotFaces Host.Snapshot/Record 面：登记面字段与会话快照汇成
// HostState；会话对象不在 = failed/session_not_built。
func TestHostSnapshotFaces(t *testing.T) {
	h := &Host{rec: HostRecord{ID: "abcd", Name: "甲"}}
	hs := h.Snapshot()
	if hs.State != "failed" || hs.Reason != "session_not_built" || hs.ID != "abcd" || hs.Name != "甲" {
		t.Fatalf("无会话的快照面：%+v", hs)
	}
	if h.Record().ID != "abcd" {
		t.Fatal("Record 面应回登记记录")
	}
}
