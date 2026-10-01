package daemon

// artifact_cli.go — 状态工件命令面（role-management tasks 3.5：1.3 内核
// nodestate.Export/Import/ResetCache 的 CLI 接线；归属 = 一次性直跑）：
//
//	homeway export [--state D] [dest.tar]   不变量四件打包（默认 homeway-export-<ts>.tar 于当前目录）
//	homeway import <file> [--state D]       布局校验 + 安全解包 + 落位序（目标进程在跑 = 拒绝）
//	homeway reset cache [--state D]         清 cache/（在跑拒绝；不碰 L1/L2 与 migration-backup）
//
// 退出码：成功 0；可行动错误（在跑拒绝/缺件/路径违规/坏工件）非零且文案给出下一步。

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/zhaoyswd/homeway/internal/nodestate"
)

// ExportCLI `homeway export`（cmd/homeway 分发；w = 提示输出）。
func ExportCLI(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway export", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（L1+L2 所在）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	dest := fmt.Sprintf("homeway-export-%s.tar", time.Now().Format("20060102-150405"))
	if fs.NArg() > 1 {
		return fmt.Errorf("export 至多一个位置参数（目标文件），got %q", fs.Args())
	}
	if fs.NArg() == 1 {
		dest = fs.Arg(0)
	}
	if err := nodestate.Export(*stateDir, dest); err != nil {
		return fmt.Errorf("export 失败：%w", err)
	}
	fmt.Fprintf(w, "已导出：%s（不变量四件 = config.toml + serve/ + relay/ + client/；0600、未压缩 tar）\n", dest)
	return nil
}

// ImportCLI `homeway import <file>`。
func ImportCLI(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway import", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（落位目标；进程必须在停）")
	if err := fs.Parse(flagsFirst(args, cliBoolFlags)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("import 需要 <file>（homeway export 产出的 tar 工件）")
	}
	if err := nodestate.Import(*stateDir, fs.Arg(0)); err != nil {
		return fmt.Errorf("import 失败：%w", err)
	}
	fmt.Fprintf(w, "已导入 %s → %s（旧四件备份于 .import-old-*；身份与 token 连续）\n", fs.Arg(0), *stateDir)
	return nil
}

// ResetCacheCLI `homeway reset cache`（两词动词）。
func ResetCacheCLI(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway reset cache", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（cache/ 所在）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("reset cache 不接受位置参数（got %q）", fs.Args())
	}
	if err := nodestate.ResetCache(*stateDir); err != nil {
		return fmt.Errorf("reset cache 失败：%w", err)
	}
	fmt.Fprintln(w, "cache/ 已清（日志/端点缓存可弃层；L1/L2 与 migration-backup-* 不动；下次启动自动重建）")
	return nil
}

// ResetCLI `homeway reset` 分发（v1 唯一动词 = cache；未知动词可行动报错）。
func ResetCLI(args []string, w io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(w, "用法：homeway reset cache [--state D]（清可弃层 cache/；进程在跑拒绝）")
		return errors.New("reset 需要动词：cache")
	}
	if args[0] == "cache" {
		return ResetCacheCLI(args[1:], w)
	}
	return fmt.Errorf("reset 不认识的动词 %q（可用：cache）", args[0])
}
