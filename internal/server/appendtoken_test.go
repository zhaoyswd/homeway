package server

// appendtoken_test.go — AppendToken 台账写入纪律（role-management 2.4 的 API 层
// 单测；serve 装配接线随批 2）。五条（tasks 2.4 清单）：
// ①端点变化 → 追加且 secret 不变 ②无变化不追加 ③全新 state 首启（预热行
// endpoints=null）→ 首轮即追加、末行 = 在跑 token ④迁移后首启（台账末行陈旧）→
// 首轮即追加 ⑤末行取掩码与控制面 token 同源断言。

import (
	"testing"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

var testEps = []proto.Endpoint{{Addr: "1.2.3.4:41641"}, {Addr: "5.6.7.8:41641", Relay: true}}

func openTestState(t *testing.T) *State {
	t.Helper()
	st, err := OpenState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// lastSecretAndLineCount 台账末行 secret 与总行数（经 Secrets——与 reg 验证同一条
// 读路径，读序 = 行序）。
func lastSecretAndLineCount(t *testing.T, st *State) ([32]byte, int) {
	t.Helper()
	secrets, err := st.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) == 0 {
		t.Fatal("空台账")
	}
	return secrets[len(secrets)-1], len(secrets)
}

func TestAppendTokenEndpointChange(t *testing.T) {
	// ①端点变化 → 追加且 secret 不变（在用 secret 复用，绝不 rand.Read 新签）。
	st := openTestState(t)
	var secret [32]byte
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	if err := st.AppendToken(secret, testEps[:1]); err != nil {
		t.Fatal(err)
	}
	newEps := append([]proto.Endpoint{}, testEps...)
	if err := st.AppendToken(secret, newEps); err != nil {
		t.Fatal(err)
	}
	gotSecret, n := lastSecretAndLineCount(t, st)
	if n != 2 {
		t.Fatalf("端点变化应追加：台账 %d 行", n)
	}
	if gotSecret != secret {
		t.Fatal("追加行的 secret 必须与在用 secret 一致（复用，不是新签发）")
	}
}

func TestAppendTokenNoChangeNoAppend(t *testing.T) {
	// ②无变化（secret + endpoints 都同）不追加。
	st := openTestState(t)
	var secret [32]byte
	secret[0] = 9
	if err := st.AppendToken(secret, testEps); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendToken(secret, testEps); err != nil {
		t.Fatal(err)
	}
	if _, n := lastSecretAndLineCount(t, st); n != 1 {
		t.Fatalf("无变化不应追加：台账 %d 行", n)
	}
}

func TestAppendTokenFreshStateFirstRound(t *testing.T) {
	// ③全新 state 首启：IssueToken(nil) 预热（endpoints=null）→ 首轮铸出（在用
	// secret + 实时端点）即追加、末行 = 在跑 token。
	st := openTestState(t)
	tok, err := st.IssueToken(nil) // 预热（现网 = serve.Run 零参首启路径）
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AppendToken(tok.Secret, testEps); err != nil {
		t.Fatal(err)
	}
	gotSecret, n := lastSecretAndLineCount(t, st)
	if n != 2 {
		t.Fatalf("预热行 + 首轮追加应 2 行：got %d", n)
	}
	if gotSecret != tok.Secret {
		t.Fatal("末行 secret 应 = 在用（预热行）secret")
	}
	last := st.lastRecordOrFatal(t)
	if len(last.Endpoints) != len(testEps) || last.Endpoints[0] != testEps[0] {
		t.Fatalf("末行 endpoints 应 = 在跑 token 的实时端点：%v", last.Endpoints)
	}
}

func TestAppendTokenMigratedStaleLastLine(t *testing.T) {
	// ④迁移后首启：台账末行陈旧（同 secret、旧端点）→ 首轮即追加（末行翻新）。
	st := openTestState(t)
	var secret [32]byte
	secret[31] = 7
	stale := []proto.Endpoint{{Addr: "9.9.9.9:41641"}}
	if err := st.AppendToken(secret, stale); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendToken(secret, testEps); err != nil {
		t.Fatal(err)
	}
	if _, n := lastSecretAndLineCount(t, st); n != 2 {
		t.Fatalf("末行陈旧应追加翻新：台账 %d 行", n)
	}
	if last := st.lastRecordOrFatal(t); len(last.Endpoints) != 2 {
		t.Fatalf("末行应为新端点：%v", last.Endpoints)
	}
}

func TestAppendTokenLastLineSameSourceAsControlPlane(t *testing.T) {
	// ⑤同源断言：控制面 reveal 铸的 token（Encode→Decode）与台账末行是同一把
	// secret + 同一组端点——「末行 = 最近在用 token」。
	st := openTestState(t)
	var secret [32]byte
	secret[5] = 0xAA
	if err := st.AppendToken(secret, testEps); err != nil {
		t.Fatal(err)
	}
	s, err := proto.EncodeToken(proto.Token{Secret: secret, Endpoints: testEps})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := proto.DecodeToken(s)
	if err != nil {
		t.Fatal(err)
	}
	gotSecret, _ := lastSecretAndLineCount(t, st)
	if tok.Secret != gotSecret {
		t.Fatal("控制面 token 的 secret 与台账末行不同源")
	}
	last := st.lastRecordOrFatal(t)
	for i := range testEps {
		if last.Endpoints[i] != tok.Endpoints[i] {
			t.Fatal("控制面 token 的端点与台账末行不同源")
		}
	}
}

// lastRecordOrFatal 测试助手：读台账末行（解析后的记录形态）。
func (s *State) lastRecordOrFatal(t *testing.T) *tokenRecordLike {
	t.Helper()
	rec, err := s.lastRecord()
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("台账为空")
	}
	return &tokenRecordLike{Secret: rec.Secret, Endpoints: rec.Endpoints}
}

// tokenRecordLike 测试读形态（tokenRecord 是未导出结构，这里只取断言要用的两字段）。
type tokenRecordLike = tokenRecord
