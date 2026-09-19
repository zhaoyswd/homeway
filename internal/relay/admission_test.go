package relay

import (
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 腿总数上限：匿名 Hello 洪水不能把表无限撑大。
func TestMaxLegsCapsTable(t *testing.T) {
	r := startRelay(t, Config{MaxLegs: 2})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	a := newFakeBackend(t, relayAddr)
	b := newFakeBackend(t, relayAddr)
	c := newFakeBackend(t, relayAddr)
	if !a.register() || !b.register() {
		t.Fatal("前两个应当注册成功")
	}
	if c.register() {
		t.Fatal("超过腿上限后不该再接受新后端")
	}
	r.mu.Lock()
	n := len(r.legs)
	r.mu.Unlock()
	if n > 2 {
		t.Fatalf("腿表不该超过上限：%d", n)
	}
	_ = time.Now
}

// token 模式：带正确密钥的后端能注册；密钥不对/没带 token 的注册被拒。
// 这就是"中继自己发凭据"的准入——中继侧不需要预先知道任何后端身份。
func TestTokenModeAdmission(t *testing.T) {
	var secret [32]byte
	rand.Read(secret[:])
	r := startRelay(t, Config{Secret: secret})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	withToken := newFakeBackend(t, relayAddr)
	withToken.psk = secret
	if !withToken.register() {
		t.Fatal("带正确 token 的后端应当注册成功")
	}
	noToken := newFakeBackend(t, relayAddr)
	if noToken.register() {
		t.Fatal("没带 token 的后端不该注册成功")
	}
	wrongToken := newFakeBackend(t, relayAddr)
	rand.Read(wrongToken.psk[:])
	if wrongToken.register() {
		t.Fatal("密钥不对的后端不该注册成功")
	}
	if st := r.Stats(); st.Registered != 1 || st.Forged < 2 {
		t.Fatalf("计数不符：%+v", st)
	}
}

// 中继 token 能编能解，里面带着地址与鉴权密钥（后端 --relay 用它）。
func TestRelayTokenRoundTrip(t *testing.T) {
	var secret [32]byte
	rand.Read(secret[:])
	tok, err := proto.EncodeRelayToken(secret, []proto.Endpoint{{Addr: "1.2.3.4:41741"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 4 || tok[:3] != "rl1" {
		t.Fatalf("前缀不对：%q", tok[:4])
	}
	got, err := proto.DecodeRelayToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != secret || len(got.Endpoints) != 1 || got.Endpoints[0].Addr != "1.2.3.4:41741" {
		t.Fatalf("解析结果不符：%+v", got)
	}
}
