// q01_race_test.go — B11 Q-01：hub.Close 与并发 transit 注入的竞态压测。
//
// 疑点（绿野评审）：Close 与并发注入（Write 分流 / Read 出站 / app 设备所有者关闭）
// 可能竞态 panic。跑法（判据）：
//
//	go test -race ./clientcore/internal/wgcore/ -run TestQ01 -count=50
//
// 断言：全程无 panic（-race 下无 DATA RACE）；Close 后 Read 有界返回（errHubClosed 或
// 残留包）、Write 走错误返回路径（app 已关时）。
package wgcore

import (
	"os"
	"sync"
	"testing"
	"time"
)

// flakyTUN：Close 后 Write 返回错误（模拟「app 设备被其所有者关闭」的真实窗口——
// hub 不关外部设备，但 Core.Close 会关 fdTUN，两者与并发注入交错）。
type flakyTUN struct {
	blockingTUN
	mu     sync.Mutex
	closed bool
}

func (f *flakyTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	return len(bufs), nil
}

func (f *flakyTUN) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return f.blockingTUN.Close()
}

func TestQ01HubCloseConcurrentTransit(t *testing.T) {
	app := &flakyTUN{blockingTUN: *newBlockingTUN()}
	bsrc := newBlockingTUN()
	h := newHub(bsrc, v4Addr("100.64.0.1"), 1280)
	if err := h.AttachTUN(app); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// 注入者：B 地址与应用地址混合（Write 的两条分流路径）。
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			pkt := make([]byte, 48)
			pkt[0] = 0x45
			for {
				select {
				case <-stop:
					return
				default:
				}
				if g%2 == 0 {
					copy(pkt[16:20], []byte{100, 64, 0, 1})
				} else {
					copy(pkt[16:20], []byte{10, 126, 126, 2})
				}
				_, _ = h.Write([][]byte{pkt}, 0)
			}
		}(g)
	}
	// 读者：出站合并通道（与 Close 的 dead 分支竞态）。
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bufs := [][]byte{make([]byte, 2048)}
			sizes := make([]int, 1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = h.Read(bufs, sizes, 0)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	h.Close()   // 并发注入中：中途 Close
	app.Close() // 所有者关 app（模拟 Core.Close 的 fdTUN.Close）
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Close 后：Read 有界返回（残留包可先被读出，但必须最终 errHubClosed、不得挂死）。
	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	gotErr := false
	for i := 0; i < 4096; i++ {
		if _, err := h.Read(bufs, sizes, 0); err != nil {
			gotErr = true
			break
		}
	}
	if !gotErr {
		t.Fatal("Close 后 Read 未在有界次数内返回错误（挂死风险）")
	}
	// Close 后 Write：app 已关 → 错误返回路径（不得 panic）。
	pkt := make([]byte, 48)
	pkt[0] = 0x45
	copy(pkt[16:20], []byte{10, 126, 126, 2})
	if _, err := h.Write([][]byte{pkt}, 0); err != nil {
		t.Logf("Close 后 Write 返回错误（合法路径）：%v", err)
	}
	// 二次 Close 幂等。
	if err := h.Close(); err != nil {
		t.Fatalf("二次 Close 应幂等：%v", err)
	}
}
