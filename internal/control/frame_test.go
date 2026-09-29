package control

// frame_test.go — §3.1 帧封装单测：编解码往返、op 码位表、帧长上限先验断连
// （不读 body——长度探针）、流 body 前缀、畸形负例。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTripAllOps(t *testing.T) {
	for op := range opNames {
		body := []byte{0xde, 0xad, 0xbe, 0xef}
		wire := EncodeFrame(op, body)
		gotOp, gotBody, err := ReadFrame(bytes.NewReader(wire), MaxControlBody)
		if err != nil || gotOp != op || !bytes.Equal(gotBody, body) {
			t.Fatalf("op=0x%02x 往返失败：err=%v op=0x%02x body=%x", op, err, gotOp, gotBody)
		}
	}
}

func TestFrameEmptyBodyAndLenIsBigEndian(t *testing.T) {
	// 空 body 帧：len=0，仍可完整读写。
	wire := EncodeFrame(OpGoodbye, nil)
	if len(wire) != 5 || wire[4] != 0 {
		t.Fatalf("空 body 帧编码形状不对：%x", wire)
	}
	op, body, err := ReadFrame(bytes.NewReader(wire), MaxControlBody)
	if err != nil || op != OpGoodbye || len(body) != 0 {
		t.Fatalf("空 body 往返失败：%v %x", err, body)
	}
	// len 字段大端：手拼 [0x10][00 00 00 02][ab cd]。
	wire = []byte{OpReq, 0x00, 0x00, 0x00, 0x02, 0xab, 0xcd}
	op, body, err = ReadFrame(bytes.NewReader(wire), MaxControlBody)
	if err != nil || op != OpReq || !bytes.Equal(body, []byte{0xab, 0xcd}) {
		t.Fatalf("大端 len 解码失败：%v %v %x", err, op, body)
	}
}

// lenProbeReader 长度探针：统计实际读出的字节数（「超限不读 body」的判据）。
type lenProbeReader struct {
	r    io.Reader
	read int64
}

func (p *lenProbeReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	return n, err
}

func TestFrameOverLimitRejectedBeforeReadingBody(t *testing.T) {
	// 声明长度 = 上限+1：帧头 5 字节后必须立即拒绝，body 一字节都不读。
	var head [5]byte
	head[0] = OpReq
	binary.BigEndian.PutUint32(head[1:5], uint32(MaxControlBody+1))
	body := make([]byte, 8) // 留在流里的 body（读走了就露馅）
	probe := &lenProbeReader{r: io.MultiReader(bytes.NewReader(head[:]), bytes.NewReader(body))}
	op, got, err := ReadFrame(probe, MaxControlBody)
	if !errors.Is(err, ErrBadFrame) {
		t.Fatalf("超限必须 ErrBadFrame，得到 %v", err)
	}
	if op != OpReq || got != nil {
		t.Fatalf("超限时不应产出 body：op=0x%02x body=%v", op, got)
	}
	if probe.read != 5 {
		t.Fatalf("超限拒绝必须不读 body：实际读了 %d 字节（期望恰 5 字节帧头）", probe.read)
	}
}

func TestFrameAtLimitAccepted(t *testing.T) {
	// 恰在上限 = 合法（≤ 上限）。
	body := make([]byte, MaxControlBody)
	wire := EncodeFrame(OpReq, body)
	_, got, err := ReadFrame(bytes.NewReader(wire), MaxControlBody)
	if err != nil || len(got) != MaxControlBody {
		t.Fatalf("恰在上限应放行：%v len=%d", err, len(got))
	}
}

func TestFrameStreamBodyLimitUsesOwnCap(t *testing.T) {
	// 流 DATA 帧用 256KiB 上限：同样先验、超限不读 body。
	var head [5]byte
	head[0] = OpStreamData
	binary.BigEndian.PutUint32(head[1:5], uint32(MaxStreamBody+1))
	probe := &lenProbeReader{r: io.MultiReader(bytes.NewReader(head[:]), bytes.NewReader(make([]byte, 4)))}
	_, _, err := ReadFrame(probe, MaxStreamBody)
	if !errors.Is(err, ErrBadFrame) {
		t.Fatalf("流帧超限必须 ErrBadFrame，得到 %v", err)
	}
	if probe.read != 5 {
		t.Fatalf("流帧超限拒绝必须不读 body：实际读了 %d 字节", probe.read)
	}
}

func TestFrameTruncatedBody(t *testing.T) {
	// 声明 10 字节只给 3 字节：io.ErrUnexpectedEOF（半帧 = 连接层按 IO 错误断连）。
	wire := []byte{OpEvt, 0x00, 0x00, 0x00, 0x0a, 1, 2, 3}
	_, _, err := ReadFrame(bytes.NewReader(wire), MaxControlBody)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("截断 body 应 ErrUnexpectedEOF，得到 %v", err)
	}
}

func TestValidOpTable(t *testing.T) {
	valid := []byte{OpHello, OpWelcome, OpReload, OpGoodbye, OpReq, OpRsp, OpEvt, OpResync, OpStreamData, OpStreamEnd}
	for _, op := range valid {
		if !ValidOp(op) {
			t.Fatalf("0x%02x 应为合法 op", op)
		}
	}
	// 预留段与任意未知值都非法（含 0x00、0x05–0x0F、0x30…）。
	invalid := []byte{0x00, 0x05, 0x0f, 0x14, 0x1f, 0x22, 0x2f, 0x30, 0xff}
	for _, op := range invalid {
		if ValidOp(op) {
			t.Fatalf("0x%02x 应为非法 op", op)
		}
		if OpName(op) != "" {
			t.Fatalf("0x%02x 不应有规范名", op)
		}
	}
}

func TestStreamBodyCodec(t *testing.T) {
	// 正常往返 + 二进制脏数据（0x00/0xff/换行/UTF-8 截断段）逐字节透传。
	payload := []byte{0x00, 0xff, 0x0a, 0x00, 0xe4, 0xb8, 0xad, 0xc3, 0x28}
	body := EncodeStreamBody(7, payload)
	id, got, err := DecodeStreamBody(body)
	if err != nil || id != 7 || !bytes.Equal(got, payload) {
		t.Fatalf("流 body 往返失败：%v id=%d got=%x", err, id, got)
	}
	// 空 payload：body 恰 4 字节。
	body = EncodeStreamBody(0xffffffff, nil)
	id, got, err = DecodeStreamBody(body)
	if err != nil || id != 0xffffffff || len(got) != 0 {
		t.Fatalf("空 payload 流 body：%v %d %x", err, id, got)
	}
	// 短于前缀 = ErrBadFrame。
	_, _, err = DecodeStreamBody([]byte{1, 2, 3})
	if !errors.Is(err, ErrBadFrame) {
		t.Fatalf("短前缀应 ErrBadFrame，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "bad_frame") {
		t.Fatalf("错误文案应含错误码字样：%v", err)
	}
}
