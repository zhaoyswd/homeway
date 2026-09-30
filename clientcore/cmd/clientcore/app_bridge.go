//go:build cshared

// app_bridge.go — 桥宿主（openspec app-service-session 任务 1.1/1.2；承载自
// app-bridge-uds 起为沙箱内 Unix socket，见 app-bridge-transport 规格）。
// tunnel-speedtest 起为三座桥（files/term/speedtest）。
//
// 把 files/term 两座桥从 tunRunner 抽成独立宿主（第三座 speedtest 后加）：监听、**首包令牌鉴权**、经
// 「拨出口本机端口」的回调进会话，全部收敛在这里。两个宿主共用同一份代码：
//   - 隧道宿主（扩展进程）：tunRunner 在 attached 时 start、世代收工时 stop；
//   - 服务会话宿主（App 进程）：app_service.go 起停（VPN 未连接时承载 files/term）。
//
// 消费方（files 模块 / terminal HSP / term LIST-KILL）只连 <filesDir>/bridge/*.sock
// （路径与令牌随状态 JSON 分发），桥 hosted 在哪个进程对它们透明。
//
// 鉴权（为什么仍然要）：socket 落在应用自己的沙箱里，其它应用不可达，但同 UID
// 的进程仍可按路径连入（沙箱隔离挡的是「别的应用」，不是「本应用的别的进程」）——
// 不鉴权的桥等于把出口 $HOME 读写与 shell 免费送给任意应用。协议：连接建立后
// 客户端**先**发 48 字节（16B 魔数 + 32B 本会话随机令牌）再进各自协议；服务端
// 读满校验，不匹配立即断开且**不向对端回写任何字节**（不给探测者反馈面）。
// 令牌每次 start 随机生成、只经状态 JSON（bridgeAuth = hex(魔数+令牌)）分发，
// 不落盘、不进日志。消费方拿到的是完整首包 blob，魔数常量只在 Go 侧存在。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wgcore"
	"github.com/zhaoyswd/homeway/pkg/speedtest"
)

// bridgeDirName 桥 socket 的子目录（<filesDir>/bridge/）。socket 路径随状态 JSON
// 分发，这里只定目录形态。
const bridgeDirName = "bridge"

// maxUnixSocketPath sockaddr_un.sun_path 的保守上限（darwin 实际 104 / linux 108）。
const maxUnixSocketPath = 100

// bridgeSocketPath 桥 socket 路径：<dir>/bridge/<name>.sock（dir = filesDir）。
func bridgeSocketPath(dir, name string) string {
	return filepath.Join(dir, bridgeDirName, name+".sock")
}

// bridgeDirFromCfg 从 tunConfig 推桥目录：IdentityDir 的父目录 = filesDir。
// 契约：两个 ArkTS 调用点（TierVpnExtensionAbility / ServiceSession）都以
// `${filesDir}/identity` 构造 identityDir——改任何一侧都要同步另一侧。
func bridgeDirFromCfg(cfg tunConfig) string {
	if cfg.IdentityDir == "" {
		return ""
	}
	return path.Dir(cfg.IdentityDir)
}

// 桥并发上限（闸的定义与旧实现一致：只防重试循环失控，正常永远到不了上限）。
const (
	filesBridgeMaxConns = 8
	termBridgeMaxConns  = 16
	speedBridgeMaxConns = 10 // 测速一组 4 流 + 重跑余量（tunnel-speedtest）
)

// bridgeAuthMagic 首包鉴权魔数（16 字节；只在本文件与状态 JSON 的 blob 里存在，
// C++/ArkTS 消费方拿到的已经是「魔数+令牌」的完整 blob，无需复刻常量）。
var bridgeAuthMagic = []byte("TIERBRIDGEAUTH01")

// bridgeAuthLen 鉴权首包总长：16B 魔数 + 32B 令牌。
const bridgeAuthLen = 48

// bridgeAuthTimeout 读鉴权首包的期限：正常消费方连上即发；留 5s 只为兜慢启动。
const bridgeAuthTimeout = 5 * time.Second

// termServicePort 出口的终端服务虚拟端口（与 homewayd term 服务默认值一致；
// 用 HOMEWAY_TERM_PORT 改过端口时，这里也要设同名环境变量）。
func termServicePort() uint16 {
	if v := os.Getenv("HOMEWAY_TERM_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return uint16(n)
		}
	}
	return 7724
}

// bridgeConns 桥接连接的并发闸（含**满员自愈**）。桥不占 gVisor 数据面的流保险阀
// （maxTCPFlows），得有自己的闸；而闸只增不减有个已知脆弱性：对端泄漏的连接
// （客户端 bug，真机 2026-09-20 实测过）会把 pipeBoth 永久挂在对端读上、占死坑位。
// 所以满员时**不拒绝**，而是挤掉最老的一条（正常使用连接只活几秒，最老的几乎
// 必是泄漏的；即便误伤，也只是断一条可重连的桥连接，好过整个桥被打死）。
type bridgeConns struct {
	mu      sync.Mutex
	live    []net.Conn // 按 accept 顺序（最老在前）
	n       atomic.Int64
	evicted atomic.Uint64
}

// admit 登记一条连接；满员时挤掉最老的一条并返回它供关闭（pipeBoth 随之退出）。
func (b *bridgeConns) admit(c net.Conn, logf func(string, ...any), what string, max int64) {
	var evict net.Conn
	b.mu.Lock()
	if int64(len(b.live)) >= max && len(b.live) > 0 {
		evict = b.live[0]
		b.live = b.live[1:]
	}
	b.live = append(b.live, c)
	b.mu.Unlock()
	if evict != nil {
		if n := b.evicted.Add(1); n <= 5 || n%50 == 0 {
			logf("%s: 并发已达上限 %d，挤掉最老的一条连接自愈（累计 %d；疑似客户端泄漏——正常使用连接只活几秒）",
				what, max, n)
		}
		_ = evict.Close()
	}
	b.n.Add(1)
}

// leave 注销一条连接（收工时调；把 conn 从活表里摘掉）。
func (b *bridgeConns) leave(c net.Conn) {
	b.mu.Lock()
	for i, x := range b.live {
		if x == c {
			b.live = append(b.live[:i], b.live[i+1:]...)
			break
		}
	}
	b.mu.Unlock()
	b.n.Add(-1)
}

// bridgeListenBackoff bind 失败（端口被占）时的重试间隔：换轨窗口里旧宿主的监听器
// 还没关、几秒内会让出来；被第三方应用长期占住时重试完如实报不可用（不再静默降级）。
var defaultBridgeListenBackoff = []time.Duration{
	250 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second,
}

// bridgeHost：两座回环桥的宿主（一个宿主一个实例；同端口同时只有一个宿主能 listen）。
type bridgeHost struct {
	what        string // 宿主描述（日志用：「隧道桥」/「服务桥」）
	dir         string // filesDir；socket 落 <dir>/bridge/*.sock（空 = 不起桥，见 start）
	logf        Logf
	dialPort    func(ctx context.Context, port uint16) (net.Conn, error)
	dialTimeout time.Duration

	mu        sync.Mutex
	stopped   bool
	filesLn   net.Listener
	termLn    net.Listener
	speedLn   net.Listener    // 测速桥（tunnel-speedtest）：第三座，宿主进程不解释帧、纯泵
	backoff   []time.Duration // listen 重试间隔（测试注入缩短；零值=默认表）
	filesOwn  os.FileInfo     // bind 出的 socket 文件身份（stop 只删自己的——防误删接管者）
	termOwn   os.FileInfo
	speedOwn  os.FileInfo
	filesSock string
	termSock  string
	speedSock string
	token     []byte // 32B；start 时生成，stop 时清零

	filesLim  bridgeConns
	termLim   bridgeConns
	speedLim  bridgeConns
	authDrops atomic.Uint64 // 鉴权失败累计（限流打日志）
}

// newBridgeHost 构造（未启动）。dialPort = 「经会话拨出口本机端口」的接缝：
// 隧道宿主传 tunRunner 的 DialTCPPort，服务会话宿主传服务会话的 DialTCPPort。
func newBridgeHost(what, dir string, logf Logf, dialPort func(ctx context.Context, port uint16) (net.Conn, error), dialTimeout time.Duration) *bridgeHost {
	if dialTimeout <= 0 {
		dialTimeout = 15 * time.Second
	}
	return &bridgeHost{what: what, dir: dir, logf: logf, dialPort: dialPort, dialTimeout: dialTimeout}
}

// start 起桥（幂等；非阻塞——listen 重试在后台 goroutine 里做，不拖慢 attach 路径）。
// 任一座桥起不来只记状态不阻断宿主（与旧实现同理：桥是附加能力，不是数据面本体）。
func (h *bridgeHost) start() {
	h.mu.Lock()
	if h.token != nil || h.stopped {
		h.mu.Unlock()
		return // 已启动 / 已停止
	}
	if h.dir == "" {
		h.mu.Unlock()
		h.logf("%s: 没有桥目录（identityDir 未配置）—— files/term/测速 本轮不可用", h.what)
		return
	}
	if err := os.MkdirAll(filepath.Join(h.dir, bridgeDirName), 0o700); err != nil {
		h.mu.Unlock()
		h.logf("%s: 建桥目录失败（%v）—— files/term/测速 本轮不可用", h.what, err)
		return
	}
	// sockaddr_un 的 sun_path 上限（darwin 104 / linux 108 字节，取保守值）：路径超长
	// 的 bind 报 invalid argument 且重试无意义，起跑前就拦下并说清（设备上的
	// <filesDir> ≈56 字节，远在线内；2026-09-22 宿主单测踩过：长临时目录名顶过线）。
	if p := bridgeSocketPath(h.dir, "files"); len(p) >= maxUnixSocketPath {
		h.mu.Unlock()
		h.logf("%s: 桥路径超长（%d ≥ %d 字节，sun_path 上限）—— files/term 本轮不可用；把 filesDir 挪短或反馈", h.what, len(p), maxUnixSocketPath)
		return
	}
	// 测速桥路径比 files 长 4 字节（speedtest.sock vs files.sock），极端下可能
	// 「files 能用、测速超长」——只跳过测速桥自己，不得连累 files/term（评审补②）。
	h.filesSock = bridgeSocketPath(h.dir, "files")
	h.termSock = bridgeSocketPath(h.dir, "term")
	if p := bridgeSocketPath(h.dir, "speedtest"); len(p) >= maxUnixSocketPath {
		h.speedSock = ""
		h.logf("%s: 测速桥路径超长（%d ≥ %d 字节）—— 测速本轮不可用（files/term 不受影响）", h.what, len(p), maxUnixSocketPath)
	} else {
		h.speedSock = p
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		h.mu.Unlock()
		// crypto/rand 失败极罕见；无令牌宁可不 exposing 桥（鉴权是硬要求，不做明文回退）。
		h.logf("%s: 生成桥令牌失败（%v）—— files/term/测速 本轮不可用", h.what, err)
		return
	}
	h.token = tok
	h.mu.Unlock()
	go h.listenAndServe()
}

// listenAndServe 后台起两座桥：bind 失败按 bridgeListenBackoff 重试（可被 stop 打断）。
// 两座各自一个 goroutine：一座端口被占重试不拖另一座。
func (h *bridgeHost) listenAndServe() {
	go func() {
		if ln := h.listenLoop("files-bridge", h.filesSock); ln != nil {
			h.acceptLoop(ln, filesNativePort, &h.filesLim, filesBridgeMaxConns, "files-bridge")
		}
	}()
	go func() {
		if ln := h.listenLoop("term-bridge", h.termSock); ln != nil {
			h.acceptLoop(ln, termServicePort(), &h.termLim, termBridgeMaxConns, "term-bridge")
		}
	}()
	if h.speedSock != "" {
		go func() {
			if ln := h.listenLoop("speed-bridge", h.speedSock); ln != nil {
				h.acceptLoop(ln, speedtestServicePort, &h.speedLim, speedBridgeMaxConns, "speed-bridge")
			}
		}()
	}
}

// listenLoop 带重试的 UDS listen（返回 nil = 重试耗尽或已被 stop）。
// 残留处理按「死/活」区分（评审整改 2026-09-22）：先拨一下现有路径——拨得通 =
// 活宿主占着（不删它的文件，listen 自然 address in use → 走退避让位）；拨不通
// （ECONNREFUSED/ENOENT）才是死残留，删掉重绑。此前「应用自己 unlink 一定失败」
// 的前提对 Go 的 raw unlink(2) 不成立（ArkTS fileIo 的实测矩阵不覆盖 syscall 路径）：
// 盲删会让本实例抢走路径、旧宿主退场时经 Close 再把新宿主的 socket 删掉，换轨
// 窗口里两败俱伤。listen 成功后记录文件身份，删除统一走 removeSockOwn。
func (h *bridgeHost) listenLoop(name, sockPath string) net.Listener {
	for attempt := 0; ; attempt++ {
		h.mu.Lock()
		stopped := h.stopped
		h.mu.Unlock()
		if stopped {
			return nil
		}
		if !sockPathFree(sockPath) { // 活宿主占着：不删，listen 报 in use → 让位退避
		} else {
			_ = os.Remove(sockPath) // 死残留（前主人异常退出没清文件）
		}
		ln, err := net.Listen("unix", sockPath)
		if err == nil {
			if ul, ok := ln.(*net.UnixListener); ok {
				ul.SetUnlinkOnClose(false) // Close 不再按路径 unlink，删除走 removeSockOwn 身份比对
			}
			own, serr := os.Stat(sockPath)
			h.mu.Lock()
			if h.stopped { // stop 抢在 listen 成功之间：立即关掉
				h.mu.Unlock()
				_ = ln.Close()
				if serr == nil {
					removeSockOwn(sockPath, own)
				} else {
					_ = os.Remove(sockPath)
				}
				return nil
			}
			if serr == nil {
				if name == "files-bridge" {
					h.filesLn, h.filesOwn = ln, own
				} else if name == "speed-bridge" {
					h.speedLn, h.speedOwn = ln, own
				} else {
					h.termLn, h.termOwn = ln, own
				}
			} else {
				if name == "files-bridge" {
					h.filesLn = ln
				} else if name == "speed-bridge" {
					h.speedLn = ln
				} else {
					h.termLn = ln
				}
			}
			h.mu.Unlock()
			h.logf("%s: %s unix:%s → 出口虚拟端口（经会话）监听中", h.what, name, sockPath)
			return ln
		}
		backoff := h.backoff
		if backoff == nil {
			backoff = defaultBridgeListenBackoff
		}
		if attempt >= len(backoff) {
			h.logf("%s: %s 监听 unix:%s 失败（%v）——重试 %d 次后放弃，本轮不可用（换轨让位或目录异常）",
				h.what, name, sockPath, err, attempt)
			return nil
		}
		time.Sleep(backoff[attempt])
	}
}

// sockPathFree：现有 socket 路径是否无主（ENOENT）或主人已死（ECONNREFUSED =
// 只剩文件没人监听）。拨得通或状态不明都按「有活主人」返回 false（保守：不删
// 状态不明的东西）。
func sockPathFree(sockPath string) bool {
	c, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
	if err == nil {
		_ = c.Close()
		return false
	}
	// ENOTSOCK（darwin：路径是普通文件——异常残留的另一种形态）、ECONNREFUSED
	// （只剩文件没人监听）与 ENOENT 都算无主；其余（拨得通/超时/状态不明）保守算有主。
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENOTSOCK)
}

// removeSockOwn：只删「还是自己 bind 出来的那个文件」；路径已被其它宿主接管
// （SameFile 不匹配）时不动它。Go 的 UnixListener.Close 默认还会按路径再 unlink
// 一次——listen 处已 SetUnlinkOnClose(false) 关掉，删除只走这里。
func removeSockOwn(path string, own os.FileInfo) {
	if own == nil {
		_ = os.Remove(path)
		return
	}
	cur, err := os.Stat(path)
	if err != nil {
		return
	}
	if os.SameFile(own, cur) {
		_ = os.Remove(path)
	}
}

// stop 收工（幂等）：关两座监听器（accept 循环随之退出），已建立的桥接连接随会话
// 关闭自然断。令牌清零——状态面此后读到空 bridgeAuth，消费方自然失败（桥也没了）。
func (h *bridgeHost) stop() {
	h.mu.Lock()
	h.stopped = true
	fl, tl, sl := h.filesLn, h.termLn, h.speedLn
	fs, ts, ss := h.filesSock, h.termSock, h.speedSock
	h.filesLn, h.termLn, h.speedLn = nil, nil, nil
	h.filesSock, h.termSock, h.speedSock = "", "", ""
	h.token = nil
	h.mu.Unlock()
	fo, to, so := h.filesOwn, h.termOwn, h.speedOwn
	h.filesOwn, h.termOwn, h.speedOwn = nil, nil, nil
	if fl != nil {
		_ = fl.Close()
		removeSockOwn(fs, fo)
	}
	if tl != nil {
		_ = tl.Close()
		removeSockOwn(ts, to)
	}
	if sl != nil {
		_ = sl.Close()
		removeSockOwn(ss, so)
	}
	h.logf("%s: 已停止监听", h.what)
}

// sockJSON 当前三座桥的 socket 路径（状态 JSON 的 bridgeFilesSock/bridgeTermSock/bridgeSpeedSock）；
// 桥未起/已停为空串——消费方据此自然失败（与 bridgeAuth 清空同拍）。
func (h *bridgeHost) sockJSON() (files, term, speed string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.token == nil {
		return "", "", ""
	}
	return h.filesSock, h.termSock, h.speedSock
}

// authHex 当前鉴权首包 blob 的 hex（魔数+令牌，96 hex 字符）；桥未起/已停为空串。
// 只进状态 JSON（bridgeAuth 键），不进日志。
func (h *bridgeHost) authHex() string {
	h.mu.Lock()
	tok := h.token
	h.mu.Unlock()
	if len(tok) != 32 {
		return ""
	}
	blob := make([]byte, 0, bridgeAuthLen)
	blob = append(blob, bridgeAuthMagic...)
	blob = append(blob, tok...)
	return hex.EncodeToString(blob)
}

// hostsession.Bridge 接缝的导出方法面（host-registry-daemon D1/A2）：小写方法保留
// （既有调用点零改动），导出版只做转发、供 hostsession.Session 经接口调用。
func (h *bridgeHost) Start()                             { h.start() }
func (h *bridgeHost) Stop()                              { h.stop() }
func (h *bridgeHost) AuthHex() string                    { return h.authHex() }
func (h *bridgeHost) SockJSON() (string, string, string) { return h.sockJSON() }

// bridgeWriteAuth 客户端：连上桥后**先**发鉴权首包（authHex 来自状态 JSON 的 bridgeAuth）。
func bridgeWriteAuth(c net.Conn, authHex string) error {
	blob, err := hex.DecodeString(authHex)
	if err != nil {
		return fmt.Errorf("鉴权 blob 不是合法 hex")
	}
	if len(blob) != bridgeAuthLen {
		return fmt.Errorf("鉴权 blob 长度不对（%d ≠ %d；App 还没拿到本会话令牌？）", len(blob), bridgeAuthLen)
	}
	_ = c.SetWriteDeadline(time.Now().Add(bridgeAuthTimeout))
	_, err = c.Write(blob)
	_ = c.SetWriteDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("发鉴权首包：%w", err)
	}
	return nil
}

// errBridgeAuth 鉴权失败（魔数或令牌不匹配）。
var errBridgeAuth = errors.New("鉴权首包不匹配")

// bridgeServerAuth 服务端：读满 48 字节校验；不匹配/超时/短读一律断开。
// 失败时**不回写任何字节**——对探测者而言这与「端口没人听」难以区分。
func bridgeServerAuth(c net.Conn, token []byte) error {
	if len(token) != 32 {
		return errors.New("宿主没有有效令牌（正在收工）")
	}
	buf := make([]byte, bridgeAuthLen)
	_ = c.SetReadDeadline(time.Now().Add(bridgeAuthTimeout))
	if _, err := io.ReadFull(c, buf); err != nil {
		return fmt.Errorf("读鉴权首包：%w", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	if !bytes.Equal(buf[:len(bridgeAuthMagic)], bridgeAuthMagic) || !bytes.Equal(buf[len(bridgeAuthMagic):], token) {
		return errBridgeAuth
	}
	return nil
}

// acceptLoop accept 循环：鉴权 → 经会话拨出口虚拟端口 → 双向泵。
func (h *bridgeHost) acceptLoop(ln net.Listener, port uint16, lim *bridgeConns, max int64, name string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // 监听器被关（收工）
		}
		lim.admit(c, h.logf, name, max)
		go func(c net.Conn) {
			defer lim.leave(c)
			h.mu.Lock()
			tok := h.token
			h.mu.Unlock()
			if err := bridgeServerAuth(c, tok); err != nil {
				_ = c.Close()
				// 判据行（真机 5.4：其它应用连桥应只看到这类行，且会话侧无拨号行）。
				if n := h.authDrops.Add(1); n <= 5 || n%50 == 0 {
					h.logf("%s: 回环连接鉴权失败已断开（累计 %d；多为其它应用探测本机端口）", name, n)
				}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), h.dialTimeout)
			remote, err := h.dialPort(ctx, port)
			cancel()
			if err != nil {
				h.logf("%s: 经会话拨出口 %d 失败: %v", name, port, err)
				if name == "speed-bridge" && !wgcore.IsRefusedLike(err) {
					// 按错误种类分流（评审 r2-N2；3e 去问候帧后的收口形态 r1 中-1②）：
					//   refused 类 = 出口活着、该端口没服务（出口未配置 state 目录，
					//   intercept 对豁免拨号失败回 RST）⇒ **不回帧直接关**——客户端
					//   请求后零字节 EOF ⇒ not_supported（「请升级出口」，判据②）；
					//   其余 = 出口不在/正在恢复 ⇒ 回 report{link_down}（先有界读掉
					//   客户端已写出的请求帧再回帧并有序收口，保证 report 先于任何
					//   复位送达）⇒ 页面回等待循环自动续跑。
					// 该路径在桥鉴权之后，回帧不向未鉴权探测者泄任何信息。
					speedLinkDownReply(c)
				}
				_ = c.Close()
				return
			}
			pipeBoth(h.logf, c, remote)
		}(c)
	}
}

// speedLinkDownReply 桥宿主拨出口失败（非 refused 类）时对 speed 桥回 report{link_down}
// 再关——客户端把它归 link_down（页面回等待循环自动续跑）。3e 去问候帧后客户端**先写
// 请求再读**：直接回帧后关会走 RST 路径、已发出的 report 可能被对端丢弃，故走
// pkg/speedtest.ReplyThenClose 的「读掉请求帧 → 回帧 → 有序收口」。
func speedLinkDownReply(conn net.Conn) {
	speedtest.ReplyThenClose(conn, bufio.NewReader(conn), speedtest.Report{Error: "link_down"})
}

// tokenForTest 暴露原始令牌给单测（不进任何状态面）。
func (h *bridgeHost) tokenForTest() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.token
}

// bridgeMagicForTest 单测用：魔数前缀。
func bridgeMagicForTest() []byte { return bridgeAuthMagic }
