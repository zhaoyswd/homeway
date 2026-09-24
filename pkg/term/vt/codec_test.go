//go:build (darwin || linux) && (amd64 || arm64) && cgo

// codec_test.go — 任务 1.4 的选型实测（体积/耗时）+ cell 行编码的往返一致性。
package vt

import (
	"bytes"
	"compress/gzip"
	"reflect"
	"testing"
	"time"
)

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatalf("gzip：%v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close：%v", err)
	}
	return buf.Bytes()
}

// TestSerializationChoice 是任务 1.4 的**选型实测**：用真实会话字节对比
// ①上游 snapshot API ②自定义 cell 行编码 的原始/ gzip 体积与编码耗时。
//
// 结论写在 cellcodec.go 的包注释里（选 ②：契约归属是决定性的，体积同量级）。
// 这里的数字同时是任务 7.4（真机流量对照）的**基线口径**——7.4 拿真机蜂窝流量跟它比。
func TestSerializationChoice(t *testing.T) {
	type row struct {
		name             string
		snapRaw, snapGz  int
		cellRaw, cellGz  int
		snapDur, cellDur time.Duration
	}
	var table []row
	for _, name := range []string{"session-git-log.bin", "session-hexdump.bin", "session-cjk.bin"} {
		term := newFrom(t, name)
		rows := term.Rows()
		cols, rws := term.Size()

		// ① snapshot API
		t0 := time.Now()
		snap, err := term.Snapshot()
		if err != nil {
			t.Fatalf("Snapshot：%v", err)
		}
		snapDur := time.Since(t0)
		snapGz := gzipped(t, snap)

		// ② 自定义 cell 行编码
		t0 = time.Now()
		grid := EncodeGrid(cols, rws, rows)
		cellDur := time.Since(t0)
		cellGz := gzipped(t, grid)

		table = append(table, row{
			name:    name,
			snapRaw: len(snap), snapGz: len(snapGz),
			cellRaw: len(grid), cellGz: len(cellGz),
			snapDur: snapDur, cellDur: cellDur,
		})
	}
	for _, r := range table {
		t.Logf("%-24s snapshot API: %6d B (gzip %5d B, %v)    cell 行编码: %6d B (gzip %5d B, %v)",
			r.name, r.snapRaw, r.snapGz, r.snapDur.Round(time.Microsecond),
			r.cellRaw, r.cellGz, r.cellDur.Round(time.Microsecond))
	}
	// 口径提示（写进测试日志，避免 7.4 拿错基线）：
	//   - snapshot API 编的是**整个终端状态**（含全部回滚），cell 行编码只编**视口网格**
	//     ⇒ 原始字节不可直接比；gzip 后才是同一量级的对照（回滚内容重复度高、压得狠）。
	//   - surface SNAPSHOT 要的是「视口 + 镜像窗口」，两者都远小于整机回滚。
	t.Log("口径：cell 行编码只含视口；snapshot API 含整机状态（含回滚）——比 gzip 后量级，不比原始字节")
}

// TestCellCodecRoundTrip：cell 行编码必须无损（差分与快照都建立在它之上）。
func TestCellCodecRoundTrip(t *testing.T) {
	for _, name := range []string{"session-git-log.bin", "session-hexdump.bin", "session-cjk.bin"} {
		t.Run(name, func(t *testing.T) {
			term := newFrom(t, name)
			rows := term.Rows()
			cols, rws := term.Size()
			b := EncodeGrid(cols, rws, rows)
			dc, dr, drows, err := DecodeGrid(b)
			if err != nil {
				t.Fatalf("DecodeGrid：%v", err)
			}
			if dc != cols || dr != rws {
				t.Fatalf("尺寸不一致：%dx%d vs %dx%d", cols, rws, dc, dr)
			}
			if len(drows) != len(rows) {
				t.Fatalf("行数不一致：%d vs %d", len(rows), len(drows))
			}
			for i := range rows {
				if rows[i].Y != drows[i].Y {
					t.Fatalf("第 %d 行 Y 不一致：%d vs %d", i, rows[i].Y, drows[i].Y)
				}
				if len(rows[i].Cells) != len(drows[i].Cells) {
					t.Fatalf("第 %d 行格数不一致：%d vs %d", i, len(rows[i].Cells), len(drows[i].Cells))
				}
				for j := range rows[i].Cells {
					a, b := rows[i].Cells[j], drows[i].Cells[j]
					// 编码不存 Width（客户端按字素自身宽度排版；占位格靠 Skip 判）
					// ⇒ 比对该字段之外的一切。
					a.Width = b.Width
					if !reflect.DeepEqual(a, b) {
						t.Fatalf("第 %d 行第 %d 格不一致：\n原 %+v\n解 %+v", i, j, a, b)
					}
				}
			}
		})
	}
}

// TestCellCodecRejectsBadInput：畸形载荷必须报错，不能解出半个网格（客户端拒收后要能重取）。
func TestCellCodecRejectsBadInput(t *testing.T) {
	if _, _, _, err := DecodeGrid(nil); err == nil {
		t.Error("空载荷应报错")
	}
	if _, _, _, err := DecodeGrid([]byte{99, 1, 0, 1, 0}); err == nil {
		t.Error("版本不符应报错")
	}
	term := newFrom(t, "session-cjk.bin")
	cols, rws := term.Size()
	b := EncodeGrid(cols, rws, term.Rows())
	// 截断尾部：应报错而不是返回半截网格。
	if _, _, _, err := DecodeGrid(b[:len(b)/2]); err == nil {
		t.Error("截断载荷应报错")
	}
}
