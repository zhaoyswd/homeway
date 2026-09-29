package control

// listen.go — control.sock 监听（§3.6，spec「端点与认证」）：凭证语义 = socket
// 属主（0600 + 目录 0700，同 term.sock 口径——权限位在 linux 与 darwin 都参与
// connect 判定，2026-09-29 双端最小实验实证，见 internal/server/serve.go term.sock
// 注释）；协议内无 token 类凭证字段；MUST NOT 在任何物理网络接口新增监听（UDS
// 之外无监听面）。
//
// 残留 socket 处理（HD「launchd 守护化」残留场景）：connect 探测——
//   - 探测连通 = 另一活实例占着 → 报错退出（不接管活监听点）；
//   - ENOENT / ECONNREFUSED = 死残留（监听者已死只剩文件）→ 清除后重 bind；
//   - 其它模糊结果（超时等）→ 按占用不明处理：不删状态不明的东西，报错。
// （同 internal/server listenLocalService 先例，独立实现——该函数未导出。）

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ControlSockName state 目录下的控制面 socket 文件名。
const ControlSockName = "control.sock"

// ListenControl 在 state 目录监听 control.sock：残留探测 → 清除/报错 → bind →
// 显式 chmod 0600（不依赖 umask 的偶然值）→ 目录收紧 0700（双层防御：第二层同时
// 护住 state 里的身份密钥等非 socket 文件）。
func ListenControl(stateDir string) (string, net.Listener, error) {
	sock := filepath.Join(stateDir, ControlSockName)
	if len(sock) >= 100 { // sockaddr_un.sun_path 保守上限（darwin 104 / linux 108）
		return sock, nil, fmt.Errorf("socket 路径超长（%d 字节 ≥ 100，sun_path 上限）", len(sock))
	}
	// 残留探测：连通 = 活实例占用。
	if c, derr := net.DialTimeout("unix", sock, 200*time.Millisecond); derr == nil {
		_ = c.Close()
		return sock, nil, errors.New("control.sock 已被另一个活实例占用（同 state 双实例？）")
	} else if !errors.Is(derr, syscall.ENOENT) && !errors.Is(derr, syscall.ECONNREFUSED) {
		return sock, nil, fmt.Errorf("control.sock 占用状态不明（%v），不接管", derr)
	}
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return sock, nil, fmt.Errorf("清残留 control.sock 失败：%w", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return sock, nil, err
	}
	// listen 后显式 chmod 0600（0600 即拦非属主 connect；不依赖 umask）。
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		return sock, nil, fmt.Errorf("control.sock 收紧 0600 失败：%w", err)
	}
	// 目录 0700（第二层；OpenDaemonState 已建，这里幂等再收紧并作为装配断言）。
	if err := os.Chmod(stateDir, 0o700); err != nil {
		// 与出口口径一致：目录收紧失败告警不阻断（socket 0600 那层还兜着）。
		fmt.Fprintf(os.Stderr, "homeway daemon: ⚠️ state 目录 %s 收紧 0700 失败（%v）——socket 0600 仍是边界\n", stateDir, err)
	}
	return sock, ln, nil
}
