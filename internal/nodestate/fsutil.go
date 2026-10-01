package nodestate

// fsutil.go — 包内文件系统小工具（原在 migration.go；一次性迁移删除后仅这三个
// 仍被 artifact.go / 测试消费，随迁至此）。

import "os"

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func dirExists(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// osRename 重命名（测试缝：落位失败注入）。
var osRename = os.Rename
