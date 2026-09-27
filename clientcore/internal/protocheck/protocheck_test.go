// protocheck：手机核模块引用 homeway 协议包的冒烟（wg-native-stack tasks 1.5 判据）。
// 隔离包，不依赖模块内其它代码，可用压平 modcache 独立编译运行。
package protocheck

import (
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

func TestProtoSmoke(t *testing.T) {
	var tok proto.Token
	for i := range tok.PeerID {
		tok.PeerID[i] = byte(i + 1)
	}
	for i := range tok.Secret {
		tok.Secret[i] = byte(200 - i)
	}
	tok.Endpoints = []proto.Endpoint{{Addr: "192.168.3.12:41641"}, {Addr: "1.2.3.4:443", Relay: true}}
	enc, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := proto.DecodeToken(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.PeerID != tok.PeerID || len(dec.RelayEndpoints()) != 1 {
		t.Fatalf("round-trip 不匹配: %+v", dec)
	}

	var pk [32]byte
	pk[0] = 9
	var dev proto.DevTag
	dev[0] = 3
	reg := proto.EncodeReg(tok.Secret, pk, dev, time.Now())
	if _, tag, err := proto.VerifyReg(tok.Secret, reg, time.Now(), 0); err != nil || tag != dev {
		t.Fatalf("reg verify: %v", err)
	}

	_, typ, payload, err := proto.DecodeTagged(proto.EncodeTagged(proto.RelayID(tok.PeerID), proto.FrameTypeData, []byte("x")))
	if err != nil || typ != proto.FrameTypeData || len(payload) != 1 {
		t.Fatalf("tagged frame: %v", err)
	}
}
