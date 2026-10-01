package wgcore

// transport_save_test.go — FIX-16 的落盘去抖单测：探测线索回调只改缓存内存表 +
// 投递合并信号（回调挂在收包/探测 goroutine 上，不做磁盘 IO）；落盘由 saveLoop
// 去抖合并执行；Close 同步补一次收口盘。变异红路：删 OnProbed 回调里的
// scheduleSave ⇒ 去抖测试「等文件出现」超时红；删 Close 的收口 Save ⇒ CloseFlush 红。

import (
	"os"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
)

// saveDebounce 调短并注册恢复（避免拖慢其余用例的全局窗；atomic 写，saveLoop 恒在读）。
func withSaveDebounce(t *testing.T, d time.Duration) {
	t.Helper()
	old := saveDebounce.Load()
	saveDebounce.Store(int64(d))
	t.Cleanup(func() { saveDebounce.Store(old) })
}

func learnedContains(c *wtransport.EndpointCache, addr string) bool {
	for _, e := range c.Entries(time.Now()) {
		if e.Addr.String() == addr {
			return true
		}
	}
	return false
}

// 探测线索经 Bind.DeliverProbed（生产等价路径：ProbeCandidates 应答即走它）注入：
// 回调返回即已观察进内存表，但去抖窗未满不得碰磁盘；窗满后由 saveLoop 落盘。
func TestProbedSaveDebounced(t *testing.T) {
	withSaveDebounce(t, 1200*time.Millisecond)
	lc := &logCap{}
	tr, cache, _ := newFreshTransport(t, lc, nil, nil, nil)

	tr.Core().Bind().DeliverProbed("198.51.100.7:41641")

	if !learnedContains(cache, "198.51.100.7:41641") {
		t.Fatal("回调应已把线索观察进内存表")
	}
	if _, err := os.Stat(cache.Path()); !os.IsNotExist(err) {
		t.Fatalf("去抖窗内不应落盘（回调路径必须零磁盘 IO）：stat err=%v", err)
	}
	waitFor(t, 5*time.Second, func() bool {
		_, err := os.Stat(cache.Path())
		return err == nil
	}, "去抖窗满后探测线索落盘")
}

// 不等去抖窗直接 Close：收口盘必须把窗内观察同步补写（会话重建/停机不丢线索）。
func TestCloseFlushesPendingSave(t *testing.T) {
	withSaveDebounce(t, time.Hour) // 窗拉到无限大：只有 Close 的收口盘能写
	lc := &logCap{}
	tr, cache, _ := newFreshTransport(t, lc, nil, nil, nil)

	tr.Core().Bind().DeliverProbed("198.51.100.8:41641")
	if _, err := os.Stat(cache.Path()); !os.IsNotExist(err) {
		t.Fatalf("窗内不应落盘：stat err=%v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache.Path()); err != nil {
		t.Fatalf("Close 应同步补一次收口落盘：%v", err)
	}
}

// Close 幂等（会话重建路径可能重复 Close）：第二次 Close 不得 panic/阻塞。
func TestCloseIdempotent(t *testing.T) {
	lc := &logCap{}
	tr, _, _ := newFreshTransport(t, lc, nil, nil, nil)
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = tr.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("第二次 Close 不得阻塞（closeOnce 保护）")
	}
}
