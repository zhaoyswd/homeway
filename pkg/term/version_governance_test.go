//go:build !windows

package term

// version_governance_test.go — 版本治理回归（contract-ledger tasks 5.1②③/5.2②，design D5）。
// term/surface 无版本目录（低-11），按**版本字段/版本门**回归：
//
//	②term = GREETING ver：生产问候帧（service.go → encGreeting）携带当前 termProtoVer；
//	  冻结的 v1 帧向量在当前门语义下解出同一版本（老前端 × 新守护）。decGreeting 本身
//	  不拒版本（原样返回线上版本）——「拒收」发生在桥层版本门（clientcore app_term.go
//	  `payload[0] != term.ProtoVer` → term_version），本组钉的是该门依赖的不变量：
//	  生产/冻结向量 ver == 本端、错配 ver 经解码**可区分**（不被吞）。
//	③surface = 载荷头版本：三类体（SNAPSHOT/DIFF/FETCH-ROWS 应答）体头写 surfaceVer，
//	  当前解码器对生产编码字节全绿（老前端 × 新守护——golden 布局即该版本的冻结形态）。
//	②'错配注入（5.2②）：体头版本注入 surfaceVer±1 → 版本门拒收（decSnapshotBody/
//	  decDiffBody/decFetchRowsReply 的既有 `ver != surfaceVer` 门，term_surface.go）。
//
// 命名前缀 TestVersionGovernance*：release.yml「契约台账对账门」step 以
// `-run 'TestVersionGovernance'` 点名本组（tasks 6.1 两组包之一）。

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVersionGovernanceGreetingVer(t *testing.T) {
	// 生产问候帧携带当前协议版本（service.go 问候即 encGreeting 路径）。
	p := encGreeting()
	if len(p) < 5 || p[0] != termProtoVer {
		t.Fatalf("生产 GREETING 体头应为 termProtoVer=%d：% x", termProtoVer, p)
	}
	ver, feats, err := decGreeting(p)
	if err != nil || ver != termProtoVer || feats != termFeatures {
		t.Fatalf("生产 GREETING 往返异常：ver=%d feats=%d err=%v", ver, feats, err)
	}
	// 冻结向量（frames.v1.jsonl 的 greeting 向量）在当前门语义下解出同一版本——
	// 老前端 × 新守护：v1 冻结字节不被当前解码改写。
	n := 0
	for _, v := range loadTermVectors(t) {
		if parseOp(t, v.Op) != opGreeting {
			continue
		}
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatalf("%s：payloadHex 非法：%v", v.Name, err)
		}
		gver, _, err := decGreeting(payload)
		if err != nil {
			t.Fatalf("%s：%v", v.Name, err)
		}
		if gver != termProtoVer {
			t.Fatalf("%s：冻结向量 ver=%d 与本端 termProtoVer=%d 不符（老前端语义漂移）", v.Name, gver, termProtoVer)
		}
		n++
	}
	if n == 0 {
		t.Fatal("frames.v1.jsonl 缺 greeting 向量（版本门回归失去冻结锚）")
	}
	t.Logf("greeting 向量 %d 条 ver=%d 与本端一致", n, termProtoVer)
}

func TestVersionGovernanceGreetingMismatchInjection(t *testing.T) {
	// 错配注入：ver±1 的问候帧经解码**可区分**（decGreeting 原样返回线上版本 ≠ 本端）
	// ⇒ 桥层版本门（app_term.go `payload[0] != term.ProtoVer`）必然触发 term_version，
	// 不存在「错配被解码吞掉、静默按本端版本继续」的路径。
	for _, ver := range []byte{termProtoVer - 1, termProtoVer + 1} {
		p := encGreeting()
		p[0] = ver
		got, _, err := decGreeting(p)
		if err != nil {
			t.Fatalf("ver=%d：%v", ver, err)
		}
		if got != ver {
			t.Fatalf("decGreeting 应原样返回线上版本 %d，得到 %d（版本差异被吞）", ver, got)
		}
		if got == ProtoVer {
			t.Fatalf("注入 ver=%d 与本端 ProtoVer 相等——注入无效", ver)
		}
	}
}

// governanceSurfaceBodies 三类体各一份生产编码样本（非零字段，避免全零体掩盖布局错位）。
func governanceSurfaceBodies(t *testing.T) map[string][]byte {
	t.Helper()
	snap := snapshotBody{
		Geometry: surfaceGeometry{Cols: 8, Rows: 4, Revision: 7},
		Cursor:   surfaceCursor{X: 1, Y: 2, Flags: cursorFlagVisible, Shape: 2},
		Modes:    5, Kitty: 1, Misc: 1, Title: "ver-gov",
		Scroll: scrollbar{Total: 40, Offset: 3, Len: 4},
		Grid:   []byte{0x11, 0x22, 0x33}, Mirror: []byte{0x44},
	}
	diff := diffBody{
		Geometry: surfaceGeometry{Cols: 8, Rows: 4, Revision: 8},
		Cursor:   surfaceCursor{X: 2, Y: 1, Flags: 0, Shape: 1},
		Modes:    1, Scroll: scrollbar{Total: 41, Offset: 4, Len: 4},
		Rows: []byte{0x55, 0x66}, RowCount: 1,
	}
	frr := fetchRowsReply{
		Geometry: surfaceGeometry{Cols: 8, Rows: 4, Revision: 9},
		From:     12, Count: 2, Rows: []byte{0x77, 0x88, 0x99, 0xaa},
	}
	return map[string][]byte{
		"snapshot":       encSnapshotBody(snap),
		"diff":           encDiffBody(diff),
		"fetchRowsReply": encFetchRowsReply(frr),
	}
}

// TestVersionGovernanceHelloDeclGate：FIX-29 服务端版本门（HELLO 尾随的客户端声明）。
// 三种形态都钉住：① 声明 == termProtoVer ⇒ 照常 ATTACHED；② 声明 != ⇒ ERROR(term_version)
// 拒腿（不是 bad_capability / 不是静默放行）；③ 未声明（旧客户端形态，无版本位）⇒ 照常。
// 变异自证：拆掉 service.go 的 `cverPresent && cver != termProtoVer` 分支 ⇒ ② 会收到
// ATTACHED，本用例必红。
func TestVersionGovernanceHelloDeclGate(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	// 手工组尾随 [capLen=1][caps][ver][idLen][id]：encHelloTail 恒写 termProtoVer，
	// 这里要注入任意声明值（① 用本端值、② 用 ±1）。
	helloWithVer := func(name string, ver byte) []byte {
		id := "gov-" + name
		hello := encHello(80, 24, true, name)
		hello = append(hello, 1, byte(capsSurface|capsProtoVer), ver, byte(len(id)))
		return append(hello, id...)
	}
	// ① 声明本端版本：照常接入。
	c1 := dialTerm(t, ln)
	defer c1.Close()
	if f := readTermFrameT(t, c1); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	writeTermFrame(t, c1, opHello, helloWithVer("govok", termProtoVer))
	if f := readTermFrameT(t, c1); f.op != opAttached {
		t.Fatalf("声明 == termProtoVer 应照常接入，收到 0x%02x（%q）", f.op, f.payload)
	}
	// ② 声明错配版本：ERROR(term_version) 拒腿（每档 ±1 各验一次）。
	for _, ver := range []byte{termProtoVer - 1, termProtoVer + 1} {
		c := dialTerm(t, ln)
		if f := readTermFrameT(t, c); f.op != opGreeting {
			t.Fatal("首帧应为 GREETING")
		}
		writeTermFrame(t, c, opHello, helloWithVer(fmt.Sprintf("govbad%d", ver), ver))
		f := readTermFrameT(t, c)
		_ = c.Close()
		if f.op != opError {
			t.Fatalf("声明 ver=%d 应被拒（ERROR），收到 0x%02x", ver, f.op)
		}
		code, msg, derr := decError(f.payload)
		if derr != nil || code != termErrVersion {
			t.Fatalf("错误码应为 %s，实际 %q（err=%v）", termErrVersion, code, derr)
		}
		if !strings.Contains(msg, "版本") {
			t.Fatalf("错误文案应含可行动归因（版本），实际 %q", msg)
		}
	}
	// ③ 未声明（旧客户端形态）：照常接入（raw/legacy 语义不变）。
	c3 := dialTerm(t, ln)
	defer c3.Close()
	if f := readTermFrameT(t, c3); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	writeTermFrame(t, c3, opHello, append(encHello(80, 24, true, "govlegacy"),
		encHelloTail(capsRawTerminal, true, "gov-legacy")...))
	if f := readTermFrameT(t, c3); f.op != opAttached {
		t.Fatalf("未声明版本的旧客户端形态应照常接入，收到 0x%02x（%q）", f.op, f.payload)
	}
	// ④ 声明位在而版本字节缺：畸形（bad_capability），不得被当成「未声明」放行。
	c4 := dialTerm(t, ln)
	defer c4.Close()
	if f := readTermFrameT(t, c4); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	writeTermFrame(t, c4, opHello, append(encHello(80, 24, true, "govmal"),
		encCapability(capsSurface|capsProtoVer)...))
	f4 := readTermFrameT(t, c4)
	if f4.op != opError {
		t.Fatalf("声明位在而字节缺应被拒，收到 0x%02x", f4.op)
	}
	if code, _, _ := decError(f4.payload); code != "bad_capability" {
		t.Fatalf("畸形尾随的错误码应为 bad_capability，实际 %q", code)
	}
}

func TestVersionGovernanceSurfaceBodyVer(t *testing.T) {
	// 生产三类体体头写 surfaceVer，且对当前解码器全绿（老前端 × 新守护）。
	dec := map[string]func([]byte) error{
		"snapshot":       func(b []byte) error { _, err := decSnapshotBody(b); return err },
		"diff":           func(b []byte) error { _, err := decDiffBody(b); return err },
		"fetchRowsReply": func(b []byte) error { _, err := decFetchRowsReply(b); return err },
	}
	for name, body := range governanceSurfaceBodies(t) {
		if body[0] != surfaceVer {
			t.Fatalf("%s 体头应为 surfaceVer=%d，得到 %d", name, surfaceVer, body[0])
		}
		if err := dec[name](body); err != nil {
			t.Fatalf("%s 生产编码字节对当前解码器解体失败：%v", name, err)
		}
	}
}

func TestVersionGovernanceSurfaceMismatchInjection(t *testing.T) {
	// 错配注入（5.2②）：体头版本注入 surfaceVer±1 → 版本门拒收（errTermFrame）。
	// 拆掉拒绝逻辑（静默按本端版本解）即红——「正确拒绝」是断言对象。
	dec := map[string]func([]byte) error{
		"snapshot":       func(b []byte) error { _, err := decSnapshotBody(b); return err },
		"diff":           func(b []byte) error { _, err := decDiffBody(b); return err },
		"fetchRowsReply": func(b []byte) error { _, err := decFetchRowsReply(b); return err },
	}
	vers := []byte{surfaceVer - 1, surfaceVer + 1}
	for name, orig := range governanceSurfaceBodies(t) {
		for _, ver := range vers {
			b := append([]byte(nil), orig...)
			b[0] = ver
			err := dec[name](b)
			if err == nil {
				t.Fatalf("%s 体头注入 ver=%d 被静默接受（版本门失效）", name, ver)
			}
			if !errors.Is(err, errTermFrame) {
				t.Fatalf("%s 体头注入 ver=%d 应为 errTermFrame，得到 %v", name, ver, err)
			}
		}
	}
}
