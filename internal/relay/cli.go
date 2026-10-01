// CLI：中继（relay）角色的前台单角色命令行入口（role-management 2.2，D1/D3/D8）。
// 一次性前台形态：**不改期望态**，flag 为一次性覆盖（覆盖序 flag > config > 内置默认）。
// `--state` 即统一 state 根：L2 = <state>/relay/、L3（relay.log）= <state>/cache/
// （r3 新-10 relay 简写补全）。默认监听 :41741（开放项⑥定稿——双角色同机默认共存，
// 示例即默认）。本文件只做参数解析与装配，转发逻辑在 relay.go/role.go。
package relay

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
)

// Version：二进制版本串（cmd/homeway/main.go 把 -ldflags 注入的 main.version 赋进来；
// 探测应答的构建标记由此取值，add-host-connectivity）。
var Version string

// CLI 解析中继参数并启动，阻塞到进程收到 SIGINT/SIGTERM（前台单角色形态保留自带
// 信号处理；统一进程的唯一信号入口在 daemon 装配层，D3）。
func CLI(args []string) error {
	fs := flag.NewFlagSet("homeway relay", flag.ExitOnError)
	state := fs.String("state", defaultStateDir(), "统一 state 根（L2=<state>/relay、relay.log=<state>/cache；首启自动迁移旧布局）")
	listen := fs.String("listen", ":41741", "监听地址（UDP；未显式给 = 用 config）")
	advertise := fs.String("advertise", "", "token 里公布的中继地址（逗号分隔 host:port；默认用本机网卡地址；未显式给 = 用 config）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `用法：
  homeway relay                            # 前台只跑中继（不改期望态）；启动日志里的「中继 token（rl1…）」给出口用
  homeway relay --advertise a.b.c.d:port   # 公网机才需要：指定 token 里公布的对外地址`)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if rest := fs.Args(); len(rest) > 0 {
		// 本角色**没有子命令**：位置参数一定是写错了。早先文档里写过并不存在的 `token` 子命令，
		// 它被静默忽略、把中继又起了一遍（还占了另一个端口）。宁可报错。
		return fmt.Errorf("不认识的参数：%v（前台中继直接 `homeway relay [--advertise …]`；启停/查询命令组见后续版本）", rest)
	}

	// 单实例锁（role-management 2.3：统一进程与前台单角色共用 <state>/lock——
	// 角色名归一 homeway）。
	lock, err := nodestate.AcquireInstanceLock(*state, "homeway")
	if err != nil {
		return err
	}
	defer lock.Release()

	// 三层 state 打开（含同根自动迁移 + config 缺失生成默认）；relay.log 落 cache/。
	nst, err := nodestate.OpenNodeState(*state)
	if err != nil {
		return fmt.Errorf("打开 state %s：%w", *state, err)
	}
	nst.Close()
	cfgFile, err := nodeconfig.Load(nodeconfig.Path(*state))
	if err != nil {
		return err // 坏 config = fail-fast（同 serve 口径）
	}

	// 覆盖序：flag 显式设值 > config > 内置默认。
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	addr := cfgFile.Relay.Listen
	if explicit["listen"] {
		addr = *listen
	}
	adv := cfgFile.Relay.Advertise
	if explicit["advertise"] {
		adv = *advertise
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return NewRole(RoleConfig{
		Addr:      addr,
		Advertise: adv,
		StateDir:  filepath.Join(*state, "relay"),
		LogDir:    filepath.Join(*state, "cache"),
		Build:     Version,
	}).Run(ctx)
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./homeway-state"
	}
	return filepath.Join(home, ".config", "homeway")
}

// loadSecret：从 state 目录加载中继鉴权密钥；没有就生成一个（0600）。
// 重启不变 ⇒ 打印出来的 token 稳定，后端不用跟着改。
func loadSecret(stateDir string) ([32]byte, bool, error) {
	var secret [32]byte
	path := filepath.Join(stateDir, "relay.key")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		copy(secret[:], b)
		return secret, false, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return secret, false, err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return secret, false, err
	}
	if err := os.WriteFile(path, secret[:], 0o600); err != nil {
		return secret, false, err
	}
	return secret, true, nil
}
