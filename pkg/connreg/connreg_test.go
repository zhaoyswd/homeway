package connreg

import (
	"net"
	"testing"
	"time"
)

// sliceConn 一个**不可比较**的 net.Conn 包装（带切片字段）——直接拿它当 map 键会
// 在插入时 panic；本表按 id 记账必须照常工作（FIX-73 的回归判据）。
type sliceConn struct {
	net.Conn
	tag []byte
}

func TestRegistryAcceptsUncomparableConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var r Registry
	id, ok := r.Add(&sliceConn{Conn: a, tag: []byte("x")}, 0)
	if !ok || id == 0 {
		t.Fatalf("不可比较的包装 conn 应能登记：id=%d ok=%v", id, ok)
	}
	if r.Len() != 1 {
		t.Fatalf("Len=%d", r.Len())
	}
	r.Remove(id)
	if r.Len() != 0 {
		t.Fatal("Remove 后应为空")
	}
}

func TestRegistryCapAndCloseAll(t *testing.T) {
	var r Registry
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	if _, ok := r.Add(c1, 1); !ok {
		t.Fatal("第一条应受理")
	}
	if _, ok := r.Add(c2, 1); ok {
		t.Fatal("达上限应拒（caller 自行关 conn）")
	}
	_ = c2.Close()
	var lingered int
	n := r.CloseAll(func(c net.Conn) { lingered++ })
	if n != 1 || lingered != 1 {
		t.Fatalf("CloseAll 应回调并关 1 条：n=%d cb=%d", n, lingered)
	}
	if r.Len() != 0 {
		t.Fatal("CloseAll 后应清表")
	}
	// 关闭真实生效（读端应看到 EOF）。
	_ = c1.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := c1.Read(buf); err == nil {
		t.Fatal("连接应已被关闭")
	}
}
