package servercore

// batch_test.go — FIX-91（统一线格式）的接收侧判据：
//  1. 容器帧 [reg][data] 一次调用内先登记后投递（保 1 RTT 的搭车语义）；
//  2. 只含 reg 的容器被内部消费（不投递）；
//  3. 非帧包（裸 WG/垃圾）不再投递——统一线格式后所有腿都是 [0xBB] 帧。

import (
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/conn"
)

func newBatchTestBind(t *testing.T) *ServerBind {
	t.Helper()
	tb := NewDeviceTable(newFakeCfg(), [][32]byte{testSecret}, DeviceConfig{MaxDevices: 4})
	b := &ServerBind{Table: tb, Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestBatchRegisterThenDeliver(t *testing.T) {
	b := newBatchTestBind(t)
	data := []byte("wg-handshake-batch")
	raw := proto.EncodeBatch(
		proto.BatchMsg{Type: proto.FrameTypeReg, Payload: regFor(pubN(1), devN(1), time.Now())},
		proto.BatchMsg{Type: proto.FrameTypeData, Payload: data},
	)
	packets := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	src := netip.MustParseAddrPort("127.0.0.1:41000")
	n, err := b.processPacket(packets, sizes, eps, raw, src)
	if err != nil || n != 1 || string(packets[0][:sizes[0]]) != string(data) {
		t.Fatalf("容器投递失败：n=%d err=%v data=%q", n, err, packets[0][:sizes[0]])
	}
	if b.Table.Len() != 1 {
		t.Fatalf("容器内 reg 未登记（保 1 RTT 语义破坏）：Len=%d", b.Table.Len())
	}
}

func TestBatchRegOnlyConsumed(t *testing.T) {
	b := newBatchTestBind(t)
	raw := proto.EncodeBatch(
		proto.BatchMsg{Type: proto.FrameTypeReg, Payload: regFor(pubN(2), devN(2), time.Now())},
	)
	packets := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	src := netip.MustParseAddrPort("127.0.0.1:41001")
	n, err := b.processPacket(packets, sizes, eps, raw, src)
	if err != nil || n != 0 {
		t.Fatalf("只含 reg 的容器应被内部消费：n=%d err=%v", n, err)
	}
	if b.Table.Len() != 1 {
		t.Fatalf("reg 未登记：Len=%d", b.Table.Len())
	}
}

func TestBatchMalformedDropped(t *testing.T) {
	b := newBatchTestBind(t)
	// 截断的容器（消息头都不完整）。
	raw := proto.EncodeFrame(proto.FrameTypeBatch, []byte{proto.FrameTypeData, 0x00})
	packets := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := b.processPacket(packets, sizes, eps, raw, netip.MustParseAddrPort("127.0.0.1:41002"))
	if err != nil || n != 0 {
		t.Fatalf("畸形容器应丢弃：n=%d err=%v", n, err)
	}
}

func TestNonFramePacketDropped(t *testing.T) {
	b := newBatchTestBind(t)
	// 裸 WG 首包（旧客户端形态）：统一线格式后不再投递。
	raw := []byte{1, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}
	packets := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := b.processPacket(packets, sizes, eps, raw, netip.MustParseAddrPort("127.0.0.1:41003"))
	if err != nil || n != 0 {
		t.Fatalf("非帧包应被丢弃（统一线格式）：n=%d err=%v", n, err)
	}
}
