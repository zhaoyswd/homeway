//go:build windows

// term_service_windows.go — Windows 桩：终端服务需要 unix 的 pty/信号/进程树语义，
// 本平台不提供（启动时打一行警告并继续提供 exit-node/files）。
package term

import (
	"net"
)

func termDisabledByEnv() bool { return false }

// termService 在 Windows 上只有形状（serve seam 需要同名类型，编译期保证两边方法集一致）。
type termService struct{}

// New 构造（Windows 桩）。
func New(logf Logf) *termService { return &termService{} }

// Disabled 报告环境变量是否显式关闭了终端服务（桩平台恒 false）。
func Disabled() bool { return false }

func (s *termService) Port() uint16         { return 0 }
func (s *termService) ShellText() string    { return "" }
func (s *termService) HistoryText() string  { return "" }
func (s *termService) ServeConn(c net.Conn) { _ = c.Close() }
func (s *termService) Close()               {}

// FeaturesText Windows 桩：无能力位。
func FeaturesText() string { return "" }
