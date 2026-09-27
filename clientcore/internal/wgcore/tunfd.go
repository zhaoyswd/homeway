package wgcore

// tunfd.go：把 VPN 扩展递进来的 TUN **裸 fd** 变成 wireguard-go 的 tun.Device。
//
// 为什么自己写而不是用现成的：扩展持有这个 fd（系统框架给的），核只读写、**不接管所有权**
// （旧核同结论，见 tunmode.go 里「不持有 TUN fd 的 *os.File」那条注释）。OHOS 的 TUN
// 与 Linux TUN 同 ABI：读=一个完整 IP 包、写=一个完整 IP 包，接口名/IFF_TUN/IFF_NO_PI
// 由系统在建立 VPN 时设好（核侧只做诊断，见 logFdInfo）。

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// fdTUN 实现 tun.Device（读/写整个 IP 包；无链路层头）。
//
// fd 读写走裸 syscall（不包 *os.File）：①不引入 GC finalizer 关掉扩展 fd 的风险；
// ②EINTR 明确重试（旧核踩过「把 EINTR 当错误 → fd 读循环退出」）。
// Close 只关自己的事件通道：fd 由扩展/系统框架回收，阻塞中的 read 会在 fd 被收回时报错返回。
type fdTUN struct {
	fd  int
	mtu int

	events chan tun.Event
	once   sync.Once
	closed chan struct{}
}

// NewTunFromFD 用裸 fd 造 tun.Device（**不关闭调用方传入的 fd 所有权语义**：
// Close 只关我们自己的 *os.File 包装；扩展那边由系统框架回收）。
func NewTunFromFD(fd, mtu int) (tun.Device, error) {
	if fd < 0 {
		return nil, errors.New("wgcore: 非法 TUN fd")
	}
	if mtu <= 0 {
		mtu = 1280
	}
	d := &fdTUN{
		fd:     fd,
		mtu:    mtu,
		events: make(chan tun.Event, 4),
		closed: make(chan struct{}),
	}
	d.events <- tun.EventUp
	return d, nil
}

func (d *fdTUN) Name() (string, error) { return "tier-tun", nil }

// File：恒 nil —— **刻意不把 fd 包成 *os.File**（旧核同结论）：os.File 带 GC finalizer，
// 一旦被回收就会替扩展把 fd 关掉（fd 所有权在扩展/系统框架那边）。
func (d *fdTUN) File() *os.File { return nil }

func (d *fdTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	buf := bufs[0][offset:]
	for {
		// 每轮循环顶查 closed（review #15）：OHOS 的 VPN fd 非阻塞，读循环的常态是
		// EAGAIN → poll(500ms) → EAGAIN……只查入口的话，hub.Close 之后读循环会在
		// 这个圈里转一辈子（fd 没关、read 永远 EAGAIN）。收工语义：closed 即 ErrClosed。
		select {
		case <-d.closed:
			return 0, os.ErrClosed
		default:
		}
		n, err := syscall.Read(d.fd, buf)
		if err != nil {
			// EINTR 是中断不是结束（旧核在这里踩过：把 EINTR 当错误会让 fd 读循环退出）
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// EAGAIN：OHOS 的 VPN fd 是**非阻塞**的（2026-09-20 真机实测：裸读立即返回
			// EAGAIN，被当错误上报会当场把健康隧道判死）。对齐旧核：poll 等 POLLIN 再读。
			if errors.Is(err, syscall.EAGAIN) {
				pfd := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
				if _, perr := unix.Poll(pfd, 500); perr != nil {
					if errors.Is(perr, unix.EINTR) {
						continue
					}
					return 0, perr
				}
				// poll 返回（就绪或超时）后也要查一次 closed——这是读循环在收工后
				// 唯一的必经点，保证 hub.Close 后 ≤~500ms 内退出。
				select {
				case <-d.closed:
					return 0, os.ErrClosed
				default:
				}
				continue
			}
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL) {
				return 0, os.ErrClosed
			}
			return 0, err
		}
		// packet-info 头自动探测（OHOS 不需要 PI，但读侧保留探测以防万一；
		// 旧核 tunmode 的 ipProtoAt 同款判定）：4 字节 PI 后面跟合法 IP 版本号才剥。
		if n >= 5 && buf[0] == 0 && buf[1] == 0 {
			if (buf[2] == 0x08 && buf[3] == 0x00 && buf[4]>>4 == 4) ||
				(buf[2] == 0x86 && buf[3] == 0xdd && buf[4]>>4 == 6) {
				copy(buf, buf[4:n])
				n -= 4
			}
		}
		sizes[0] = n
		return 1, nil
	}
}

func (d *fdTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		for {
			if _, err := syscall.Write(d.fd, pkt); err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				if errors.Is(err, syscall.EAGAIN) {
					pfd := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLOUT}}
					if _, perr := unix.Poll(pfd, 500); perr != nil {
						if errors.Is(perr, unix.EINTR) {
							continue
						}
						return 0, perr
					}
					continue
				}
				if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL) {
					return 0, os.ErrClosed
				}
				return 0, err
			}
			break
		}
	}
	return len(bufs), nil
}

func (d *fdTUN) MTU() (int, error) { return d.mtu, nil }
func (d *fdTUN) Events() <-chan tun.Event {
	return d.events
}
func (d *fdTUN) BatchSize() int { return 1 }

func (d *fdTUN) Close() error {
	d.once.Do(func() {
		close(d.closed)
		close(d.events)
	})
	// 不关 fd：所有权在扩展/系统框架那边（旧核同结论）。
	return nil
}
