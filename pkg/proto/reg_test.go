package proto

import (
	"errors"
	"testing"
	"time"
)

func TestRegRoundTrip(t *testing.T) {
	var secret, pubkey [32]byte
	for i := range secret {
		secret[i], pubkey[i] = byte(i), byte(200-i)
	}
	now := time.Now()
	pkt := EncodeReg(secret, pubkey, now)
	got, err := VerifyReg(secret, pkt, now.Add(time.Second), 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != pubkey {
		t.Fatal("pubkey 不匹配")
	}
}

func TestRegWrongSecret(t *testing.T) {
	var secret, other, pubkey [32]byte
	for i := range secret {
		secret[i], other[i], pubkey[i] = 1, 2, 3
	}
	pkt := EncodeReg(secret, pubkey, time.Now())
	if _, err := VerifyReg(other, pkt, time.Now(), 0); !errors.Is(err, ErrRegBadMAC) {
		t.Fatalf("err = %v, want ErrRegBadMAC", err)
	}
}

func TestRegExpired(t *testing.T) {
	var secret, pubkey [32]byte
	pkt := EncodeReg(secret, pubkey, time.Now())
	if _, err := VerifyReg(secret, pkt, time.Now().Add(5*time.Minute), 0); !errors.Is(err, ErrRegExpired) {
		t.Fatalf("err = %v, want ErrRegExpired", err)
	}
}

func TestRegMalformed(t *testing.T) {
	var secret, pubkey [32]byte
	pkt := EncodeReg(secret, pubkey, time.Now())
	if _, err := VerifyReg(secret, pkt[:10], time.Now(), 0); !errors.Is(err, ErrRegMalformed) {
		t.Fatalf("err = %v, want ErrRegMalformed", err)
	}
}
