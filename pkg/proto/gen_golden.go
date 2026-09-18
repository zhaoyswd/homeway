//go:build ignore

// 一次性 golden 向量生成器：go run gen_golden.go，把输出钉进 token_test.go。
package main

import (
	"fmt"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

func main() {
	var t proto.Token
	for i := range t.PeerID {
		t.PeerID[i] = byte(i + 1)
	}
	for i := range t.Secret {
		t.Secret[i] = byte(255 - i)
	}
	t.Endpoints = []proto.Endpoint{
		{Addr: "192.0.2.12:41641", Relay: false},
		{Addr: "exit.example.net:41641", Relay: false},
		{Addr: "203.0.113.9:4430", Relay: true},
	}
	s, err := proto.EncodeToken(t)
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
}
