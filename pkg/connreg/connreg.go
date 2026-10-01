// Package connreg：连接登记表（net.Conn 集合）——按自增 id 记账，**不拿 net.Conn
// 当 map 键**（FIX-73）。
//
// 为什么：`map[net.Conn]V` 要求接口背后的**动态类型可比较**——socks/speedtest/dns
// 三处曾各写一份，今天插的都是 *net.TCPConn（可比较、安全），但任何一层将来包一个
// 带切片/映射字段的包装 conn，插入即 panic（本项目历史上踩过同形态事故）。改按 id
// 记账后，包装类型随便带什么字段都能安全登记。
package connreg

import (
	"net"
	"sync"
)

// Registry 并发安全的连接登记表（零值可用）。
type Registry struct {
	mu   sync.Mutex
	next uint64
	m    map[uint64]net.Conn
}

// Add 登记一条连接；max > 0 且已满时返回 ok=false（**由调用方**负责关掉它——各消费
// 面关连接的方式不同：RST/优雅/记账）。上限判定与插入在同一临界区（原子，不会有
// 「检查后又被别人塞满」的窗口）。
func (r *Registry) Add(c net.Conn, max int) (id uint64, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max > 0 && len(r.m) >= max {
		return 0, false
	}
	if r.m == nil {
		r.m = make(map[uint64]net.Conn)
	}
	r.next++
	r.m[r.next] = c
	return r.next, true
}

// Remove 摘除（收工时调用；幂等）。
func (r *Registry) Remove(id uint64) {
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
}

// Len 在册条数。
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// CloseAll 关掉全部在册连接并清表（收工/off 用）；before 非 nil 时逐条先回调
// （如 SetLinger(0) 的 RST 收口），返回关掉的条数。
func (r *Registry) CloseAll(before func(net.Conn)) int {
	r.mu.Lock()
	conns := make([]net.Conn, 0, len(r.m))
	for _, c := range r.m {
		conns = append(conns, c)
	}
	r.m = nil
	r.mu.Unlock()
	for _, c := range conns {
		if before != nil {
			before(c)
		}
		_ = c.Close()
	}
	return len(conns)
}

// Snapshot 在册连接快照（诊断/测试用）。
func (r *Registry) Snapshot() []net.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]net.Conn, 0, len(r.m))
	for _, c := range r.m {
		out = append(out, c)
	}
	return out
}
