package control

// version_governance_test.go — 版本治理回归（contract-ledger tasks 5.1①/5.2①，design D5）：
//
//	①老前端 × 新守护：控制面 fixtures 按**版本目录**遍历（今天 v1，未来 v2…）对当前
//	  生产解码器全绿——旧版本语义预期跨升级保持（「字段只增不改 + 解码忽略未知字段」
//	  使旧向量永续有效）。fixtures_test.go 的对拍经 loadFixtures 已自动遍历全部版本
//	  目录；本文件把「目录遍历」本身钉成判据：新版本目录落盘即自动进回归、空目录
//	  幂等跳过（临时造 v2/ 空目录不炸）。
//	②版本错配注入红路：握手携带当前不支持的 protoVersion（伪高/伪低）→ reload
//	  （proto_mismatch）后断连、无半解——锚定 handleHello 既有行为（锁步哲学：
//	  唯一协商位，无降级路径），行为不新造、只补回归锚。
//
// 命名前缀 TestVersionGovernance*：release.yml「契约台账对账门」step 以
// `-run 'TestVersionGovernance'` 点名本组（tasks 6.1 两组包之一；contracts 侧
// 版本空间对拍在同命令的 ./contracts/... 全量里）。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

// TestVersionGovernanceFixtureDirs 老前端 × 新守护：每个版本目录独立子测试，对当前
// 生产解码器全绿。未来 v2/ 目录落盘（新增向量 = 只增）自动出现在本测试与
// loadFixtures 全部对拍里；v1 缺席即红（冻结基线不可删）。
func TestVersionGovernanceFixtureDirs(t *testing.T) {
	root := filepath.Join("testdata", "fixtures")
	dirs := fixtureVersionDirs(t, root)
	seenV1 := false
	total := 0
	for _, dir := range dirs {
		seenV1 = seenV1 || dir == "v1"
		t.Run(dir, func(t *testing.T) {
			entries := loadFixturesDir(t, root, dir)
			if dir == "v1" && len(entries) == 0 {
				t.Fatalf("v1 版本目录没有向量（冻结基线缺席 = 异常）")
			}
			for _, fx := range entries {
				replayFixtureDecode(t, fx)
			}
			total += len(entries)
			t.Logf("版本目录 %s：%d 向量对当前生产解码器全绿", dir, len(entries))
		})
	}
	if !seenV1 {
		t.Fatalf("版本目录缺 v1（现：%v）", dirs)
	}
	if total == 0 {
		t.Fatal("全部版本目录合计 0 向量（空集假绿）")
	}

	// 空目录幂等：临时根下造 v2/ 空目录——遍历不炸、零向量（tasks 5.1 验证项）。
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := fixtureVersionDirs(t, tmp); len(got) != 1 || got[0] != "v2" {
		t.Fatalf("临时根版本目录遍历异常：%v", got)
	}
	if entries := loadFixturesDir(t, tmp, "v2"); len(entries) != 0 {
		t.Fatalf("空目录应幂等跳过（0 向量），得到 %d", len(entries))
	}
}

// TestVersionGovernanceHandshakeProtoMismatch 版本错配注入（tasks 5.2①）：握手注入
// protoVersion±1（伪高/伪低两个方向）→ 断言回 reload（原因 proto_mismatch）后连接
// 关闭、无半解（未握手态不发 welcome；断连后的请求无应答）。
func TestVersionGovernanceHandshakeProtoMismatch(t *testing.T) {
	for _, delta := range []int{-1, +1} {
		ver := ProtoVersion + delta
		t.Run(fmt.Sprintf("ver=%d", ver), func(t *testing.T) {
			ts := startTestServer(t, facade.BusConfig{})
			nc, err := net.Dial("unix", ts.sock)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			hello := fmt.Sprintf(`{"protoVersion":%d,"frontend":{"kind":"cli","name":"raw","version":"0"}}`, ver)
			if _, err := nc.Write(EncodeFrame(OpHello, []byte(hello))); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(nc)
			op, body := readFrameRaw(t, r)
			if op != OpReload {
				t.Fatalf("protoVersion=%d 应回 reload，得到 0x%02x", ver, op)
			}
			var rl ReloadBody
			if err := json.Unmarshal(body, &rl); err != nil || rl.Reason != ReloadProtoMismatch {
				t.Fatalf("reload 原因应为 proto_mismatch：%v（%s）", err, body)
			}
			// reload 后连接关闭（读到 EOF），且不是半解：补一个请求帧也不得有任何应答
			//（写本身被 broken pipe 拒绝 = 服务端已闭合同样是「无半解」的实证）。
			if _, err := r.ReadByte(); err != io.EOF {
				t.Fatalf("reload 后应关闭连接，读到 %v", err)
			}
			if _, werr := nc.Write(EncodeFrame(OpReq, []byte(`{"op":"host.list","id":1}`))); werr == nil {
				if _, err := r.ReadByte(); err != io.EOF {
					t.Fatalf("断连后不应有应答（半解）：%v", err)
				}
			} else {
				t.Logf("断连后补写被拒（%v）——连接已闭、无半解", werr)
			}
			// 服务端从未进入已握手态：新连接正常握手仍得 welcome（前一条连接的错配
			// 不残留任何服务端状态）。
			nc2, err := net.Dial("unix", ts.sock)
			if err != nil {
				t.Fatal(err)
			}
			defer nc2.Close()
			ok := fmt.Sprintf(`{"protoVersion":%d,"frontend":{"kind":"cli","name":"raw","version":"0"}}`, ProtoVersion)
			if _, err := nc2.Write(EncodeFrame(OpHello, []byte(ok))); err != nil {
				t.Fatal(err)
			}
			r2 := bufio.NewReader(nc2)
			op2, _ := readFrameRaw(t, r2)
			if op2 != OpWelcome {
				t.Fatalf("后续正常握手应得 welcome，得到 0x%02x", op2)
			}
		})
	}
}
