package relay

import (
	"encoding/hex"
	"testing"
	"time"

	"net/netip"
)

// 白名单：列了的后端能注册，没列的连挑战都拿不到（防"知道地址就能蹭"）。
func TestAllowListBlocksStrangers(t *testing.T) {
	// 先起一个开放中继，拿两个真后端的标签
	open := startRelay(t, Config{})
	openAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), open.LocalAddr().Port())
	mine := newFakeBackend(t, openAddr)
	stranger := newFakeBackend(t, openAddr)

	// 用「我的标签」起一个白名单中继
	r := startRelay(t, Config{Allow: []string{hex.EncodeToString(mine.label[:])}})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	mine.relay = relayAddr
	if !mine.register() {
		t.Fatal("白名单里的后端应当注册成功")
	}
	stranger.relay = relayAddr
	if stranger.register() {
		t.Fatal("不在白名单里的后端不该注册成功")
	}
	if st := r.Stats(); st.Denied == 0 {
		t.Fatalf("拒绝计数没记上：%+v", st)
	}
}

// 完整公钥写法也能用（自动派生标签）。
func TestAllowListAcceptsFullPubkey(t *testing.T) {
	open := startRelay(t, Config{})
	openAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), open.LocalAddr().Port())
	be := newFakeBackend(t, openAddr)
	r := startRelay(t, Config{Allow: []string{hex.EncodeToString(be.pub[:])}})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be.relay = relayAddr
	if !be.register() {
		t.Fatal("用完整公钥配白名单时应当注册成功")
	}
}

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
