package dns

import (
	"encoding/binary"
	"testing"
)

// buildQuery 构造最小 DNS 查询：ID + header + question(name, qtype, IN)。
func buildQuery(id uint16, name string, qtype uint16) []byte {
	q := make([]byte, 0, 32)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x01 // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	q = append(q, hdr...)
	for _, label := range splitLabels(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	tq := make([]byte, 4)
	binary.BigEndian.PutUint16(tq[0:2], qtype)
	binary.BigEndian.PutUint16(tq[2:4], 1) // IN
	return append(q, tq...)
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// buildResponse 在查询后追加 N 条 A 记录（TTL 可控）。
func buildResponse(query []byte, rcode uint16, ttls ...uint32) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x80 | (query[2] & 0x01)
	resp[3] = byte(rcode & 0x0F)
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(ttls)))
	for _, ttl := range ttls {
		rec := make([]byte, 16) // name 指针(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(4)
		binary.BigEndian.PutUint16(rec[0:2], 0xC00C)
		binary.BigEndian.PutUint16(rec[2:4], 1) // A
		binary.BigEndian.PutUint16(rec[4:6], 1)
		binary.BigEndian.PutUint32(rec[6:10], ttl)
		binary.BigEndian.PutUint16(rec[10:12], 4)
		resp = append(resp, rec...)
	}
	return resp
}

func TestQType(t *testing.T) {
	for _, c := range []struct {
		qtype uint16
		want  bool
	}{{28, true}, {65, true}, {64, true}, {255, true}, {1, false}, {16, false}} {
		q := buildQuery(1, "example.com", c.qtype)
		got, ok := QType(q)
		if !ok || got != c.qtype {
			t.Fatalf("QType(%d) = %d,%v", c.qtype, got, ok)
		}
		if FilteredQType(got) != c.want {
			t.Fatalf("FilteredQType(%d) = %v, want %v", c.qtype, FilteredQType(got), c.want)
		}
	}
	if _, ok := QType([]byte{1, 2, 3}); ok {
		t.Fatal("短包不应解析出 qtype")
	}
	if _, ok := QType(buildQuery(1, "a", 1)[:14]); ok {
		t.Fatal("question 截断包不应解析出 qtype")
	}
}

func TestEmptyResponse(t *testing.T) {
	q := buildQuery(0xABCD, "example.com", 28)
	r := EmptyResponse(q)
	if r == nil {
		t.Fatal("合法查询应得到空应答")
	}
	if binary.BigEndian.Uint16(r[0:2]) != 0xABCD {
		t.Fatal("ID 应原样回显")
	}
	if r[2]&0x80 == 0 || r[2]&0x01 == 0 || r[3]&0x80 == 0 {
		t.Fatalf("QR/RD/RA 位缺失: %02x %02x", r[2], r[3])
	}
	for _, off := range [3]int{6, 8, 10} {
		if binary.BigEndian.Uint16(r[off:off+2]) != 0 {
			t.Fatal("三计数应为零")
		}
	}
	if binary.BigEndian.Uint16(r[4:6]) != 1 {
		t.Fatal("QDCOUNT 应为 1")
	}
	if EmptyResponse([]byte{1}) != nil {
		t.Fatal("畸形查询应返回 nil")
	}
}

func TestClampTTL(t *testing.T) {
	q := buildQuery(7, "slow.example", 1)
	r := buildResponse(q, 0, 7193, 120, 30)
	n := ClampTTL(r, 60)
	if n != 2 {
		t.Fatalf("应改写 2 条，got %d", n)
	}
	qd := questionEnd(r)
	if got := binary.BigEndian.Uint32(r[qd+6 : qd+10]); got != 60 {
		t.Fatalf("TTL 7193 应钳到 60，got %d", got)
	}
	if got := binary.BigEndian.Uint32(r[qd+16+6 : qd+16+10]); got != 60 {
		t.Fatalf("TTL 120 应钳到 60，got %d", got)
	}
	r2 := buildResponse(q, 0, 30)
	if ClampTTL(r2, 60) != 0 {
		t.Fatal("短 TTL 不应被改写")
	}
	if ClampTTL([]byte{1, 2}, 60) != 0 {
		t.Fatal("畸形包应返回 0")
	}
}

func TestCountAAAA(t *testing.T) {
	q := buildQuery(9, "mix.example", 1)
	r := buildResponse(q, 0, 5, 5)
	if got := CountAAAA(r); got != 0 {
		t.Fatalf("A 记录不应计为 AAAA，got %d", got)
	}
	// 手工把第二条改成 AAAA（type 字段在该 RR 的 name 指针后 2 字节）
	qd := questionEnd(r)
	binary.BigEndian.PutUint16(r[qd+18:qd+20], 28)
	if got := CountAAAA(r); got != 1 {
		t.Fatalf("夹带 AAAA 应计数 1，got %d", got)
	}
}

func TestTruncate(t *testing.T) {
	q := buildQuery(3, "big.example", 1)
	// 8 条记录的应答，截到 header+question+2 条完整记录
	r := buildResponse(q, 0, 60, 60, 60, 60, 60, 60, 60, 60)
	qd := questionEnd(r)
	limit := qd + 16*2
	out := Truncate(r, limit)
	if len(out) > limit {
		t.Fatalf("截断后应 ≤%d，got %d", limit, len(out))
	}
	if out[2]&0x02 == 0 {
		t.Fatal("TC 位应置位")
	}
	if got := binary.BigEndian.Uint16(out[6:8]); got != 2 {
		t.Fatalf("ANCOUNT 应为实存 2 条，got %d", got)
	}
	if got := binary.BigEndian.Uint16(out[8:10]); got != 0 {
		t.Fatalf("NSCOUNT 应清零，got %d", got)
	}
	// 小应答原样返回
	small := buildResponse(q, 0, 60)
	if out := Truncate(small, 1232); len(out) != len(small) {
		t.Fatal("未超限不应截断")
	}
	// 一条都放不下：只剩 header+question
	out = Truncate(r, qd+10)
	if binary.BigEndian.Uint16(out[6:8]) != 0 || out[2]&0x02 == 0 {
		t.Fatal("放不下任何记录时应只回 header+question 且 TC=1")
	}
}
