package daemon

// files_remote.go — pkg/files RemoteFiles 缝的 daemon 实现（files-cli 2.2，design
// D3/D6）：`--host` 模式的寻址与拨号都经控制面——Resolve = daemon.status 拉主机表 +
// resolveHostTarget（与 host delete/status / term 面**同一份寻址实现**）；Dial =
// control.Dial（control.sock）→ stream.open{kind:files, host} → streamConn 适配器。
// files 协议（问候帧/六动词/帧式大文件）端到端原样承载，零 wire 改动（控制面纯透传）。
//
// term_remote.go 的共享件（dialControl/controlDialErr/streamOpenErr/streamConn）
// 原样复用——本文件只有 files 面的参数化差异。

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/files"
)

// FilesRemote 构造 pkg/files 的远程接入缝实现（cmd/homeway 接线：
// files.CLI(rest, daemon.FilesRemote(version))）。
func FilesRemote(version string) files.RemoteFiles {
	return &filesRemote{version: version}
}

type filesRemote struct{ version string }

// ResolveHostRef 把 --host 的名称/全长 hex/无歧义短前缀解析为 hex id（寻址 = 与
// host delete/status、term 面同一份 resolveHostTarget：同一规则、同一歧义报错文案）。
// 预算口径与 term 面一致：解析与打开各用一次 --timeout 预算。
func (r *filesRemote) ResolveHostRef(ctx context.Context, stateDir, ref string) (string, string, error) {
	dir := stateDir
	if dir == "" {
		dir = DefaultStateDir()
	}
	// 空串错误文案按调用面参数化（term r1 P2-7 同款）：resolveHostTarget 的空串
	// 分支写死「homeway host delete」——files 面先拦，不出现 host delete。
	if strings.TrimSpace(ref) == "" {
		return "", "", errors.New("空寻址串不可用——homeway files <子命令> --host 需要 <name|id>（homeway host list 查看在表主机）")
	}
	hosts, closeC, err := fetchHostsForTerm(ctx, dir, r.version)
	if err != nil {
		return "", "", err
	}
	defer closeC()
	return resolveHostTarget(hosts, ref)
}

// DialFiles 打开到目标主机 files 服务的字节流。ctx = 「控制面连接 + stream.open」
// 预算（CLI --timeout 的第二段）；问候帧（首响应）预算由 CLI 侧看门承接（pkg/files
// 的拨号缝契约，见 files_cli.go）。
func (r *filesRemote) DialFiles(ctx context.Context, stateDir, hexID string) (io.ReadWriteCloser, error) {
	dir := stateDir
	if dir == "" {
		dir = DefaultStateDir()
	}
	c, err := dialControl(ctx, dir, r.version)
	if err != nil {
		return nil, err
	}
	st, err := c.OpenStream(ctx, facade.StreamKindFiles, hexID)
	if err != nil {
		c.Close()
		return nil, filesStreamOpenErr(err)
	}
	return &streamConn{c: c, st: st}, nil
}

// filesStreamOpenErr 层②的 files 面参数化（streamOpenErr 同源 + bad_request 的
// 代际文案——kind 值域外 = 新 CLI 配旧 daemon 的唯一兼容断点，design D5）。
func filesStreamOpenErr(err error) error {
	var code control.CodeError
	if errors.As(err, &code) {
		switch string(code) {
		case facade.CodeBadRequest:
			return errors.New("守护进程代际过旧，不识 files 流；请同批升级 daemon（bad_request：stream.open 的 kind 值域外）")
		}
	}
	return streamOpenErr(err)
}
