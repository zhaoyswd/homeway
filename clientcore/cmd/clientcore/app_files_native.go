//go:build cshared

// App 专用：文件管理会话（**files 原生协议**，wg-native-stack tasks 4.2）。
//
// 与旧实现（app_files.go 的 SSH/SFTP 那套）的关系：NAPI 契约（十个分发名、JSON 信封、
// 错误码表）**逐字保留**，只把「怎么跟出口说话」从 SFTP-over-22 换成 homewayd 的
// files 原生协议（pkg/files）：每命令一条内部流，走当前世代的传输接缝
// （`exitSession.DialTCPPort`）拨后端 127.0.0.1:7802 —— 后端按本机网络重拨到它自己的
// files 服务（根 = $HOME、恒读写、os.Root 监牢、原子上传都由服务端实现）。
//
// 传输侧不感知协议：旧栈（tailcat 出口）没有这个服务时会拿到 ERR/握手失败，
// 归因成 files_not_enabled 一类（与旧栈直连 22 的归因语义一致）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/files"
)

// filesNativePort 是 homewayd files 服务的**本机**端口（见 homeway internal/server.DefaultFilesPort）。
const filesNativePort = 7802

// filesConnectTimeout 单条命令（含问候帧）的预算。
const filesConnectTimeout = 15 * time.Second

// transferOpenBudget 传输流「开场」的有界预算（拨号 + 问候 + 请求响应）：与单命令预算同源。
// 超时还没见到第一个正文字节 = 这条流死在开场（对端不说话/半死），警戒把连接的读期限拨到
// 「立刻」，卡在无 deadline 读上的传输 goroutine 得以带错退出——否则它永久占着会话传输表
// （再点下载报 busy）与桥连接坑位。正文一旦开始流动警戒即解除，**传输体不受任何期限**
// （大文件不受限是设计意图）；正文期间的长停滞由页侧看门狗（TxWatchdog，15s 无进展）收口。
// var 是为了测试注入缩短（同 defaultBridgeListenBackoff 的做法）。
var transferOpenBudget = filesConnectTimeout

// nativeFilesSession：一条 files 会话。与旧实现一样，会话只承载「哪个主机/什么根」，
// 每个命令各自开一条内部流（协议契约：每命令一条流，无跨命令状态）。
type nativeFilesSession struct {
	id       int
	root     string
	auth     string // 桥鉴权 blob（hex；每条流首包都要发，见 nativeFilesDial）
	cli      *files.Client
	mu       sync.Mutex // 分发操作串行化（UI 本就单人串行；与旧实现同语义）
	txMu     sync.Mutex
	txs      map[int]*filesTransfer
	txNext   int
	lastUsed time.Time
}

// nativeFilesDial：**拨本机文件桥**（Unix domain socket，隧道或服务会话宿主）。
//
// 为什么不是直接拨后端：files 的 NAPI 调用发生在 **App 进程**（FilesClient.ets → tailcatFilesCall），
// 而传输/隧道在**扩展进程**里 —— App 进程的核实例没有 tunnel（`currentTunRun()` 为 nil）。
// 旧实现就是这么分工的（App → 本地桥 → 隧道 → 出口），换成原生协议后分工不变，
// 变的只是「桥那头拨到后端的 7802」（见 app_bridge.go）。
//
// sock = 桥 socket 路径、authHex = 桥鉴权首包 blob（两者都来自状态 JSON：
// bridgeFilesSock / bridgeAuth；隧道宿主经 IPC 拿、服务会话宿主直接读
// ClientCoreServiceStatus）——app-bridge-uds 起承载是沙箱内 UDS，鉴权保留为纵深。
func nativeFilesDial(ctx context.Context, authHex, sock string) (net.Conn, error) {
	if sock == "" {
		return nil, filesErrf(filesCodeBridgeDown, "文件通道暂时不可用（桥未就绪：VPN 未连接且服务会话未就绪，或正在恢复）")
	}
	conn, err := net.DialTimeout("unix", sock, filesConnectTimeout)
	if err != nil {
		return nil, filesErrf(filesCodeBridgeDown, "文件通道暂时不可用（桥未就绪或正在恢复）：%v", err)
	}
	if err := bridgeWriteAuth(conn, authHex); err != nil {
		_ = conn.Close()
		return nil, filesErrf(filesCodeBridgeAuth, "文件通道鉴权失败：%v", err)
	}
	// 读预算落到 conn deadline：pkg/files 的 Open/call 只把 ctx 用于拨流，读侧没有
	// deadline，对端「连着但不说话」时读会无限挂死（真机 2026-09-22：退后台回前台
	// 后文件页永远「连接中」，重开 VPN 才恢复）。两条**无界**来源：① 桥宿主被冻结
	// （VPN 扩展 doze——UDS 拨号由内核 backlog 代答、鉴权包进缓冲区，无人 accept/回
	// 问候，且冻结进程自己的定时器也停了，无人收尾这条连接）；② 桥已 accept 且拨号
	// 成功但远端不回问候（出口 files 半死——pipeBoth 无读期限）。另有**有界但超预算**
	// 的慢路径：挂起唤醒后恢复阶梯最长 ~32s 超过桥 15s 拨号预算，读要等阶梯收尾才见
	// EOF。一次性命令的 ctx 都带 15s 期限：到点读失败 → 归一 bridge_down → App 侧
	// 自动重试骑过恢复窗口。传输流的 ctx 无期限（大文件不受限），不设 deadline、
	// 语义不变。
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// mapNativeFilesErr 把 pkg/files 的稳定错误码透传给 NAPI（码表与 ArkTS 的
// filesErrorMessage 同一套；未知码回落 op_failed）。
func mapNativeFilesErr(err error) *filesError {
	if err == nil {
		return nil
	}
	var fe *files.Error
	if errors.As(err, &fe) {
		return &filesError{Code: fe.Code, Msg: fe.Msg}
	}
	var fdErr *filesError
	if errors.As(err, &fdErr) {
		return fdErr
	}
	return filesErrf(filesCodeOpFailed, "%s", err.Error())
}

// normalizeOpStreamErr 把**操作路径**上的流开场失败归一成 bridge_down（其余原样透传）。
//
// 判据是**稳定码**（homeway `pkg/files` 的 `files.CodeStreamOpen`，2026-09-26 起）：开场失败意味着
// 这条流根本没进出口（拨号失败/回程失效/桥宿主不在），与 connect 路径上被归一成 bridge_down 的是
// 同一件事——不归一的话，「出口暂时不可达」会以「操作失败：读问候帧失败…」的面目出现在文件页，
// App 侧也无法把它认成通道不可达（bridge-call-layer 的域码表里通道码是 `bridge_down`）去自动重试。
//
// 为什么只认开场、不认 call 阶段的「发请求失败/读响应失败」：后者可能是「请求已送达、响应丢了」，
// 而 App 侧对 bridge_down 会**自动重放**——重放不能证明未送达的操作会让写操作重复执行。
// 所以这里**只判码**：`op_failed` 一律不归一（出口侧的真实操作失败与响应丢失都编在这个码里，
// 它们是确定性/未知失败，交给分类学的「其余」档，由用户点「重试」）。
//
// 为什么不用文案前缀（旧做法）：上游改一句文案就静默失效且没有测试会红。这个码与 `pkg/files`
// 同版本发布（本地 replace / 钉版本），改任一侧都要同步本函数与 `TestNormalizeOpStreamErr`。
func normalizeOpStreamErr(fe *filesError) *filesError {
	if fe == nil || fe.Code != files.CodeStreamOpen {
		return fe
	}
	filesLogf("操作失败于流开场（归一 bridge_down 触发通道重试）：%s", fe.Msg)
	return filesErrf(filesCodeBridgeDown, "文件通道当时不可用：%s", fe.Msg)
}

// mapOpErr = 透传稳定码 + 开场失败归一（操作路径专用；connect 路径见 nativeFilesConnect）。
func mapOpErr(err error) *filesError {
	return normalizeOpStreamErr(mapNativeFilesErr(err))
}

func nativeFilesConnect(op map[string]any) (filesResult, *filesError) {
	timeoutMs := 15000
	if v, ok := op["timeoutMs"].(float64); ok && v > 0 {
		timeoutMs = int(v)
	}
	auth, _ := op["auth"].(string)
	sock, _ := op["sock"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	cli := &files.Client{Dial: func(cctx context.Context) (net.Conn, error) { return nativeFilesDial(cctx, auth, sock) }}
	greet, err := cli.Open(ctx) // 问候帧（root/ver/rw）
	if err != nil {
		// 问候阶段非 files 协议错误（稳定码 files_not_enabled/other_service 等照常透传）
		// 一律归一成 bridge_down：桥在「经会话拨出口」失败时直接关连接，客户端读问候
		// 得 EOF——本质是会话/通道当时不可用（挂起唤醒陈旧、出口刚重启、healingDial
		// 的 15s 预算内没完成重握手都会落到这里）。bridge_down 会触发 App 侧对
		// bridge_down 的自动重试（FilesPage ×5），而恢复阶梯（丢会话+补注册）已在首拨
		// 触发，第二次进来即用（真机 2026-09-20：挂起唤醒后连接 EOF 连败需手动重试）。
		mapped := mapNativeFilesErr(err)
		if mapped.Code == files.CodeOpFailed {
			filesLogf("连接失败（归一 bridge_down 触发自动重试）：%v", err)
			return nil, filesErrf(filesCodeBridgeDown, "文件通道当时不可用：%v", err)
		}
		return nil, mapped
	}
	// 问候流用完即关（协议契约 = 每命令一条流）：这条流若不关，conn 会一直挂在桥上——
	// 每次进文件页漏一条，8 次后打满桥的并发闸，之后所有连接被拒（真机 2026-09-20
	// 实测：快速进出 8 次后「刷新也没用」，日志判据 = files-bridge 并发连接已达上限）。
	root, ver := greet.Root, greet.Ver
	if err := greet.Close(); err != nil {
		filesLogf("问候流关闭失败（忽略，继续）：%v", err)
	}
	// 会话表（与旧实现同一把锁/同一驱逐策略：防"页面忘了 close"漏会话）。
	filesMu.Lock()
	if len(nativeFilesSessions) >= maxFilesSessions {
		var oldest *nativeFilesSession
		for _, s := range nativeFilesSessions {
			if oldest == nil || s.lastUsed.Before(oldest.lastUsed) {
				oldest = s
			}
		}
		if oldest != nil {
			delete(nativeFilesSessions, oldest.id)
		}
	}
	filesNext++
	s := &nativeFilesSession{
		id: filesNext, root: root, auth: auth, cli: cli,
		txs: map[int]*filesTransfer{}, lastUsed: time.Now(),
	}
	nativeFilesSessions[s.id] = s
	filesMu.Unlock()
	filesLogf("会话 #%d 已建立（原生协议，root=%s ver=%d）", s.id, root, ver)
	return filesResult{"handle": s.id, "root": root, "ver": ver}, nil
}

// nativeFilesSessions 与旧实现共用 filesMu/filesNext（两套会话表不会同时活跃，
// 共享计数与锁可避免「换了实现却漏改一处」的静默漂移）。
var nativeFilesSessions = map[int]*nativeFilesSession{}

func nativeGetSession(handle int) (*nativeFilesSession, *filesError) {
	filesMu.Lock()
	defer filesMu.Unlock()
	s := nativeFilesSessions[handle]
	if s == nil {
		return nil, filesErrf(filesCodeNoSession, "会话不存在或已关闭")
	}
	s.lastUsed = time.Now()
	return s, nil
}

func (s *nativeFilesSession) shutdown() {
	s.txMu.Lock()
	txs := make([]*filesTransfer, 0, len(s.txs))
	for _, tx := range s.txs {
		txs = append(txs, tx)
	}
	s.txs = map[int]*filesTransfer{}
	s.txMu.Unlock()
	for _, tx := range txs {
		tx.cancelOnce.Do(func() { close(tx.cancel) })
	}
}

// ---- 六动词分发 ----

func nativeFilesDispatch(opJson string) string {
	var op map[string]any
	if err := json.Unmarshal([]byte(opJson), &op); err != nil {
		return marshalFiles(nil, filesErrf(filesCodeInvalidArg, "参数不是合法 JSON：%v", err))
	}
	name, _ := op["op"].(string)
	handle := 0
	if v, ok := op["handle"].(float64); ok {
		handle = int(v)
	}
	str := func(k string) string { v, _ := op[k].(string); return v }
	int64v := func(k string, d int64) int64 {
		if v, ok := op[k].(float64); ok && v > 0 {
			return int64(v)
		}
		return d
	}

	if name == "connect" {
		res, ferr := nativeFilesConnect(op)
		return marshalFiles(res, ferr)
	}
	s, gerr := nativeGetSession(handle)
	if gerr != nil {
		return marshalFiles(nil, gerr)
	}
	var res filesResult
	var ferr *filesError
	ctx, cancel := context.WithTimeout(context.Background(), filesConnectTimeout)
	defer cancel()
	switch name {
	case "close":
		filesMu.Lock()
		delete(nativeFilesSessions, s.id)
		filesMu.Unlock()
		s.shutdown()
		filesLogf("会话 #%d 已关闭", s.id)
		res = filesResult{"ok": true}
	case "list":
		s.mu.Lock()
		ents, err := s.cli.List(ctx, str("path"))
		s.mu.Unlock()
		if err != nil {
			ferr = mapOpErr(err)
		} else {
			out := make([]filesEntry, 0, len(ents))
			for _, e := range ents {
				out = append(out, filesEntry{Name: e.Name, IsDir: e.IsDir, Size: e.Size, MtimeMs: e.MtimeMs})
			}
			res = filesResult{"entries": out}
		}
	case "stat":
		s.mu.Lock()
		e, err := s.cli.Stat(ctx, str("path"))
		s.mu.Unlock()
		if err != nil {
			ferr = mapOpErr(err)
		} else {
			res = filesResult{"entry": filesEntry{Name: e.Name, IsDir: e.IsDir, Size: e.Size, MtimeMs: e.MtimeMs}}
		}
	case "mkdir":
		s.mu.Lock()
		err := s.cli.Mkdir(ctx, str("path"))
		s.mu.Unlock()
		if err != nil {
			ferr = mapOpErr(err)
		} else {
			res = filesResult{"ok": true}
		}
	case "readText", "readImage":
		mode := ""
		def := int64(files.DefaultTextMaxBytes)
		if name == "readImage" {
			mode, def = "image", int64(files.DefaultImageMaxBytes)
		}
		s.mu.Lock()
		resp, err := s.cli.Read(ctx, str("path"), mode, int64v("maxBytes", def))
		s.mu.Unlock()
		if err != nil {
			ferr = mapOpErr(err)
		} else {
			res = filesResult{"size": resp.Size, "truncated": resp.Truncated}
			if mode == "image" {
				res["base64"] = resp.Base64
			} else {
				res["text"] = resp.Text
			}
		}
	case "download":
		res, ferr = s.startNativeTransfer("download", str("remotePath"), str("localPath"))
	case "upload":
		res, ferr = s.startNativeTransfer("upload", str("remotePath"), str("localPath"))
	case "transfers":
		res = s.nativeTransfers()
	case "cancel":
		res = s.nativeCancel(int(int64v("transferId", 0)))
	default:
		ferr = filesErrf(filesCodeInvalidArg, "未知操作 %q", name)
	}
	return marshalFiles(res, ferr)
}

// ---- 传输（进度/取消语义与旧实现对齐） ----

func (s *nativeFilesSession) startNativeTransfer(direction, remotePath, localPath string) (filesResult, *filesError) {
	if remotePath == "" || localPath == "" {
		return nil, filesErrf(filesCodeInvalidArg, "remotePath 与 localPath 必填")
	}
	if direction != "download" && direction != "upload" {
		return nil, filesErrf(filesCodeInvalidArg, "未知方向 %q", direction)
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()
	for _, tx := range s.txs {
		if !tx.done {
			return nil, filesErrf(filesCodeBusy, "已有传输进行中，请等它完成或取消")
		}
	}
	s.txNext++
	tx := &filesTransfer{
		id: s.txNext, Direction: direction, RemotePath: remotePath,
		localPath: localPath, cancel: make(chan struct{}),
	}
	s.txs[tx.id] = tx
	go s.runNativeTransfer(tx)
	return filesResult{"transferId": tx.id}, nil
}

func (s *nativeFilesSession) runNativeTransfer(tx *filesTransfer) {
	setDone := func(errText string) {
		s.txMu.Lock()
		tx.done = true
		tx.err = errText
		s.txMu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-tx.cancel:
			cancel()
		case <-ctx.Done():
		}
	}()
	// 开场警戒：随传输各自的 Dial 挂在连接上（ctx 无期限、conn 上也没有任何人设
	// deadline——pkg/files 的读只有 Upload 正文检查 ctx.Err，Download 全程不吃 ctx，
	// 所以不能走 WithTimeout，只能按连接定向断读）。第一个进度回调即解除；见
	// transferOpenBudget 注释。
	var openGuard *time.Timer
	disarm := func() {
		if openGuard != nil {
			openGuard.Stop()
		}
	}
	defer disarm()
	cli := &files.Client{Dial: func(cctx context.Context) (net.Conn, error) {
		conn, err := s.cli.Dial(cctx)
		if err != nil {
			return nil, err
		}
		openGuard = time.AfterFunc(transferOpenBudget, func() {
			filesLogf("传输 %d 开场超时（%v 无正文字节）：断读收口", tx.id, transferOpenBudget)
			_ = conn.SetReadDeadline(time.Now())
		})
		return conn, nil
	}}
	progress := func(n int64) {
		disarm() // 正文已开始流动：开场警戒解除（大文件不受限）
		s.txMu.Lock()
		tx.bytes = n
		s.txMu.Unlock()
	}
	var err error
	switch tx.Direction {
	case "download":
		var lf *os.File
		if lf, err = os.Create(tx.localPath); err != nil {
			setDone("创建本地文件：" + err.Error())
			return
		}
		defer lf.Close()
		_, err = cli.Download(ctx, tx.RemotePath, &progressWriter{w: lf, progress: progress})
		if err == nil {
			if fi, serr := lf.Stat(); serr == nil {
				s.txMu.Lock()
				tx.total = fi.Size()
				s.txMu.Unlock()
			}
		}
	case "upload":
		var lf *os.File
		if lf, err = os.Open(tx.localPath); err != nil {
			setDone("打开本地文件：" + err.Error())
			return
		}
		defer lf.Close()
		var fi os.FileInfo
		if fi, err = lf.Stat(); err == nil {
			s.txMu.Lock()
			tx.total = fi.Size()
			s.txMu.Unlock()
		}
		_, err = cli.Upload(ctx, tx.RemotePath, lf, tx.total, progress)
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			setDone("canceled: 已取消")
		} else {
			setDone(err.Error())
		}
		return
	}
	setDone("")
	filesLogf("传输 %d 完成（%s %s，%d 字节）", tx.id, tx.Direction, tx.RemotePath, tx.bytes)
}

// progressWriter 把写入进度喂给传输快照（下载用；上传由客户端回调）。
type progressWriter struct {
	w        *os.File
	progress func(int64)
	n        int64
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.n += int64(n)
	if p.progress != nil {
		p.progress(p.n)
	}
	return n, err
}

func (s *nativeFilesSession) nativeTransfers() filesResult {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	out := make([]map[string]any, 0, len(s.txs))
	for id := 1; id <= s.txNext; id++ {
		tx := s.txs[id]
		if tx == nil {
			continue
		}
		out = append(out, map[string]any{
			"id": tx.id, "direction": tx.Direction, "remotePath": tx.RemotePath,
			"bytes": tx.bytes, "total": tx.total, "done": tx.done, "err": tx.err,
		})
	}
	return filesResult{"transfers": out}
}

func (s *nativeFilesSession) nativeCancel(id int) filesResult {
	s.txMu.Lock()
	tx := s.txs[id]
	s.txMu.Unlock()
	if tx != nil {
		tx.cancelOnce.Do(func() { close(tx.cancel) })
	}
	return filesResult{"ok": true}
}
