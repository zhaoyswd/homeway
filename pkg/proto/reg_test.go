package proto

import (
	"errors"
	"testing"
	"time"
)

func TestRegRoundTrip(t *testing.T) {
	var secret, pubkey [32]byte
	var devTag DevTag
	for i := range secret {
		secret[i], pubkey[i] = byte(i), byte(200-i)
	}
	for i := range devTag {
		devTag[i] = byte(0x40 + i)
	}
	now := time.Now()
	pkt := EncodeReg(secret, pubkey, devTag, now)
	if len(pkt) != regFixedLen {
		t.Fatalf("报文长度 = %d，want %d", len(pkt), regFixedLen)
	}
	got, gotDev, err := VerifyReg(secret, pkt, now.Add(time.Second), 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != pubkey {
		t.Fatal("pubkey 不匹配")
	}
	if gotDev != devTag {
		t.Fatal("devTag 不匹配")
	}
}

func TestRegWrongSecret(t *testing.T) {
	var secret, other, pubkey [32]byte
	for i := range secret {
		secret[i], other[i], pubkey[i] = 1, 2, 3
	}
	pkt := EncodeReg(secret, pubkey, DevTag{}, time.Now())
	if _, _, err := VerifyReg(other, pkt, time.Now(), 0); !errors.Is(err, ErrRegBadMAC) {
		t.Fatalf("err = %v, want ErrRegBadMAC", err)
	}
}

func TestRegExpired(t *testing.T) {
	var secret, pubkey [32]byte
	pkt := EncodeReg(secret, pubkey, DevTag{}, time.Now())
	if _, _, err := VerifyReg(secret, pkt, time.Now().Add(5*time.Minute), 0); !errors.Is(err, ErrRegExpired) {
		t.Fatalf("err = %v, want ErrRegExpired", err)
	}
}

func TestRegMalformed(t *testing.T) {
	var secret, pubkey [32]byte
	pkt := EncodeReg(secret, pubkey, DevTag{}, time.Now())
	if _, _, err := VerifyReg(secret, pkt[:10], time.Now(), 0); !errors.Is(err, ErrRegMalformed) {
		t.Fatalf("err = %v, want ErrRegMalformed", err)
	}
}

// devTag 在 MAC 覆盖内：篡改标签必须被拒（否则可把注册写到别的设备记录上）。
func TestRegTamperedDevTag(t *testing.T) {
	var secret, pubkey [32]byte
	var devTag DevTag
	devTag[0] = 7
	pkt := EncodeReg(secret, pubkey, devTag, time.Now())
	pkt[34] ^= 0xff // 改 devTag 首字节
	if _, _, err := VerifyReg(secret, pkt, time.Now(), 0); !errors.Is(err, ErrRegBadMAC) {
		t.Fatalf("err = %v, want ErrRegBadMAC", err)
	}
}

// v1 报文（"HR"，58B）不再接受：产品未发布，不留兼容分支。
func TestRegV1Rejected(t *testing.T) {
	var secret, pubkey [32]byte
	v1 := make([]byte, 58)
	copy(v1, "HR")
	copy(v1[2:34], pubkey[:])
	if _, _, err := VerifyReg(secret, v1, time.Now(), 0); !errors.Is(err, ErrRegMalformed) {
		t.Fatalf("err = %v, want ErrRegMalformed", err)
	}
}
