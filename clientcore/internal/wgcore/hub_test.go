package wgcore

// hub_test.go — IsRefusedLike 的单元级回归（review 2026-09-21）：
//   - RST 判定统一走 wgnet.ErrRefused 哨兵（错误文本不再是唯一契约）。
//   （DNS 应答构造/截断测试随 BuildUDP53Response 删除——dns-host-resolver：
//    解析归出口代答，1232/TC 语义由 homeway pkg/dns 承担并有等价测试。）

import (
	"errors"
	"fmt"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

func TestIsRefusedLike(t *testing.T) {
	if IsRefusedLike(nil) {
		t.Fatal("nil 不算 refused")
	}
	if !IsRefusedLike(wgnet.ErrRefused) {
		t.Fatal("哨兵本体必须命中")
	}
	if !IsRefusedLike(fmt.Errorf("wgnet: connect: %w", wgnet.ErrRefused)) {
		t.Fatal("包装后的哨兵必须命中（errors.Is）")
	}
	// 不留子串兜底（本地 replace 钉版本，出口侧恒挂哨兵）：纯文本含 "refused"
	// 的错误不得命中——误吞会让 PathProbe 把「目标异常」误判成「会话活着」。
	if IsRefusedLike(errors.New("wgnet: connect: connection refused")) {
		t.Fatal("纯文本形态不得命中（只认哨兵）")
	}
	if IsRefusedLike(errors.New("i/o timeout")) {
		t.Fatal("超时被误判成 refused")
	}
}
