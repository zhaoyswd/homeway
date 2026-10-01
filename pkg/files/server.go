package files

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 与旧 NAPI 契约对齐的默认值（app_files.go：readText 512KB / readImage 8MB）。
const (
	DefaultTextMaxBytes  = 512 * 1024
	DefaultImageMaxBytes = 8 * 1024 * 1024
	// maxInlineRead 内联载荷硬上限（防止客户端要一个超大 maxBytes 把内存吃爆）。
	maxInlineRead = 16 * 1024 * 1024
	// uploadPartSuffix 原子上传的临时后缀（死在半路只留它，绝不留正式名）。
	uploadPartSuffix = ".tierpart"

	// MaxConns 并发在册流上限（FIX-36）。此前唯一界在拦截层（64 流 / 30min 空闲，
	// 见 pkg/intercept），files 服务自己无闸：拦截层上限一松（FIX-63 提到 512–1024）
	// 或经本机 UDS 直连（不经拦截层）时，服务端就没有任何并发界。超限的流回
	// busy 错误（客户端有可行动文案），不静默挂起。
	MaxConns = 16

	// IdleTimeout 每流空闲期限（FIX-36）：静默超过它即收流。与拦截层「空闲收流」
	// 同一取向（FIX-63 目标 3–5 分钟）——两层的界要能同时成立，内层不能比外层宽。
	IdleTimeout = 5 * time.Minute

	// stalePartAge 陈旧 .tierpart 的回收阈值（FIX-36）：上传中断留下的临时文件
	// 在下一次写同一路径时顺手清（只清超过这个年龄的，绝不碰正在用的）。
	stalePartAge = 24 * time.Hour
)

// Server：以某个目录为根的 files 服务（根 = 后端用户主目录，恒读写）。
type Server struct {
	root     *os.Root
	rootPath string
	logf     func(format string, args ...any)

	// 并发闸（FIX-36）：容量 MaxConns 的信号量；满则 ServeConn 快速回 busy。
	sem chan struct{}

	// idle（FIX-36，测试可改）：0 = 用 IdleTimeout。
	idleTimeout time.Duration
}

// Open 打开根目录（rootDir 为空 = 用户主目录）。不存在/不是目录 → 报错。
func Open(rootDir string) (*Server, error) {
	if rootDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		rootDir = home
	}
	rootDir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	return &Server{
		root: r, rootPath: rootDir, logf: func(string, ...any) {},
		sem: make(chan struct{}, MaxConns), idleTimeout: IdleTimeout,
	}, nil
}

// SetLogger 注入日志。
func (s *Server) SetLogger(logf func(string, ...any)) {
	if logf != nil {
		s.logf = logf
	}
}

// SetIdleTimeout 改每流空闲期限（测试/配置面；<=0 = 保持现值）。
func (s *Server) SetIdleTimeout(d time.Duration) {
	if d > 0 {
		s.idleTimeout = d
	}
}

// bufPool 帧缓冲池（FIX-36）：MaxChunk 缓冲按流申请/归还，避免每流一次 64KiB 分配。
var bufPool = sync.Pool{
	New: func() any { b := make([]byte, MaxChunk); return &b },
}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }

// idleConn 空闲期限包装（FIX-36）：每次成功读写把期限推后 idleTimeout——
// 「有流量就不收、静默超时即收」。SetDeadline 下沉到 net.Conn，对上层透明。
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

// RootDir 根目录路径（问候帧 root 字段；供 ArkTS 的 hostPathOf 图标匹配）。
func (s *Server) RootDir() string { return s.rootPath }

// Close 关闭根句柄。
func (s *Server) Close() error { return s.root.Close() }

// Serve 在 listener 上服务（每流一个 goroutine，每流一条命令）。
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
}

// ServeConn 处理一条内部流：问候帧 → 一条命令（大文件传输在本流内完成）。
//
// 并发闸（FIX-36）：在册流满 MaxConns 时**读完请求行**再回 busy——协议面是
// 「问候 → 请求 → 响应」，不回请求行而直接断会让客户端只看到流消失（归不了因）。
func (s *Server) ServeConn(conn net.Conn) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		defer conn.Close()
		br := bufio.NewReader(conn)
		if err := WriteLine(conn, Greeting{Ok: true, Root: s.rootPath, Ver: Version}); err != nil {
			return
		}
		if _, rerr := ReadRequest(br); rerr != nil {
			_ = WriteLine(conn, errorResponse(rerr))
			return
		}
		_ = WriteLine(conn, Errf(CodeServerBusy, "服务端并发流已满（%d），请稍后重试", MaxConns).response())
		s.logf("files: 并发流已满（%d）——回 busy 拒入", MaxConns)
		return
	}
	defer conn.Close()
	if s.idleTimeout > 0 {
		conn = &idleConn{Conn: conn, idle: s.idleTimeout}
	}
	br := bufio.NewReader(conn)
	// 问候帧恒第一个发（即使请求行非法，客户端也能先拿到 root/ver）。
	if err := WriteLine(conn, Greeting{Ok: true, Root: s.rootPath, Ver: Version}); err != nil {
		return
	}
	req, err := ReadRequest(br)
	if err != nil {
		_ = WriteLine(conn, errorResponse(err))
		return
	}
	if fErr := s.dispatch(conn, br, req); fErr != nil {
		_ = WriteLine(conn, fErr.response())
		s.logf("files: %s %q 失败：%s", req.Op, req.Path, fErr.Msg)
	}
}

func errorResponse(err error) Response {
	var fe *Error
	if errors.As(err, &fe) {
		return fe.response()
	}
	return Response{Ok: false, Code: "op_failed", Msg: err.Error()}
}

// dispatch 执行一条命令；返回 nil 表示已自行写过响应。
func (s *Server) dispatch(w io.Writer, br *bufio.Reader, req *Request) *Error {
	switch req.Op {
	case "list":
		ents, err := s.list(req.Path)
		if err != nil {
			return err
		}
		return writeLineErr(w, Response{Ok: true, Entries: ents})
	case "stat":
		e, err := s.stat(req.Path)
		if err != nil {
			return err
		}
		return writeLineErr(w, Response{Ok: true, Entry: e})
	case "mkdir":
		if err := s.mkdir(req.Path); err != nil {
			return err
		}
		return writeLineErr(w, Response{Ok: true})
	case "read":
		return s.read(w, req)
	case "download":
		return s.download(w, req)
	case "write":
		return s.write(w, br, req)
	default:
		return Errf(CodeInvalidArg, "未知操作 %q", req.Op)
	}
}

func writeLineErr(w io.Writer, v any) *Error {
	if err := WriteLine(w, v); err != nil {
		return Errf(CodeOpFailed, "写响应失败：%v", err)
	}
	return nil
}

// ---------- 路径沙箱 ----------

// relPath 把请求路径规整成「相对根的路径」：""/"."/"/" ⇒ "."；剥前导 "/"；
// 拒绝 NUL/控制字符与 .. 段（os.Root 还会再拒一次符号链接逃逸）。
func relPath(p string) (string, *Error) {
	if p == "" {
		return ".", nil
	}
	for _, r := range p {
		if r == 0 || r < 0x20 || r == 0x7f {
			return "", Errf(CodeInvalidArg, "路径含非法字符")
		}
	}
	// 任何 `..` 段一律拒绝（spec：`..` 穿越必须被拒绝）。注意不能只靠 Clean：
	// path.Clean("/" + "../x") = "/x"，会把越界悄悄「洗白」成根内路径。
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", Errf(CodeInvalidArg, "路径越界：%q", p)
		}
	}
	clean := path.Clean("/" + strings.TrimPrefix(p, "/")) // 钉成绝对再 Clean ⇒ 消掉 ..
	if clean == "/" {
		return ".", nil
	}
	rel := strings.TrimPrefix(clean, "/")
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", Errf(CodeInvalidArg, "路径越界：%q", p)
	}
	return rel, nil
}

func mapOSErr(op, p string, err error) *Error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Errf(CodeNotFound, "%s %s：不存在", op, p)
	case errors.Is(err, os.ErrPermission):
		return Errf(CodePermission, "%s %s：拒绝访问", op, p)
	}
	// os.Root 对逃逸（..、符号链接指向根外）返回的错误：归到 not_found，不泄漏根外信息
	if msg := err.Error(); strings.Contains(msg, "escapes from parent") || strings.Contains(msg, "outside of root") {
		return Errf(CodeNotFound, "%s %s：不存在", op, p)
	}
	return Errf(CodeOpFailed, "%s %s：%v", op, p, err)
}

func entryOf(fi os.FileInfo) Entry {
	return Entry{
		Name:    fi.Name(),
		IsDir:   fi.IsDir(),
		Size:    fi.Size(),
		MtimeMs: fi.ModTime().UnixMilli(),
		Mode:    uint32(fi.Mode().Perm()),
	}
}

// ---------- 六动词 ----------

func (s *Server) list(p string) ([]Entry, *Error) {
	rel, err := relPath(p)
	if err != nil {
		return nil, err
	}
	f, oerr := s.root.Open(rel)
	if oerr != nil {
		return nil, mapOSErr("list", p, oerr)
	}
	defer f.Close()
	fis, oerr := f.ReadDir(-1)
	if oerr != nil {
		return nil, mapOSErr("list", p, oerr)
	}
	out := make([]Entry, 0, len(fis))
	for _, de := range fis {
		if de.Name() == "." || de.Name() == ".." {
			continue
		}
		fi, err := de.Info()
		if err != nil {
			continue // 竞态下条目消失：跳过（列表是快照语义）
		}
		out = append(out, entryOf(fi))
	}
	return out, nil
}

func (s *Server) stat(p string) (*Entry, *Error) {
	rel, err := relPath(p)
	if err != nil {
		return nil, err
	}
	fi, oerr := s.root.Stat(rel)
	if oerr != nil {
		return nil, mapOSErr("stat", p, oerr)
	}
	e := entryOf(fi)
	return &e, nil
}

func (s *Server) mkdir(p string) *Error {
	rel, err := relPath(p)
	if err != nil {
		return err
	}
	name := path.Base(rel)
	if rel == "." || name == "." || name == "/" || name == "" {
		return Errf(CodeInvalidName, "目录名不合法：%q", name)
	}
	if strings.Contains(name, "/") {
		return Errf(CodeInvalidName, "目录名不合法：%q", name)
	}
	if _, oerr := s.root.Stat(rel); oerr == nil {
		return Errf(CodeAlreadyExists, "同名条目已存在")
	}
	if oerr := s.root.Mkdir(rel, 0o755); oerr != nil {
		return mapOSErr("mkdir", p, oerr)
	}
	return nil
}

func (s *Server) read(w io.Writer, req *Request) *Error {
	rel, err := relPath(req.Path)
	if err != nil {
		return err
	}
	fi, oerr := s.root.Stat(rel)
	if oerr != nil {
		return mapOSErr("read", req.Path, oerr)
	}
	if fi.IsDir() {
		return Errf(CodeIsDir, "是目录，不是文件")
	}
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		if req.Mode == "image" {
			maxBytes = DefaultImageMaxBytes
		} else {
			maxBytes = DefaultTextMaxBytes
		}
	}
	if maxBytes > maxInlineRead {
		maxBytes = maxInlineRead
	}
	f, oerr := s.root.Open(rel)
	if oerr != nil {
		return mapOSErr("read", req.Path, oerr)
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, rerr := io.ReadFull(f, buf)
	if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
		return mapOSErr("read", req.Path, rerr)
	}
	res := Response{Ok: true, Size: fi.Size(), Truncated: fi.Size() > int64(n)}
	if req.Mode == "image" {
		res.Base64 = base64.StdEncoding.EncodeToString(buf[:n])
	} else {
		res.Text = string(buf[:n])
	}
	return writeLineErr(w, res)
}

// download：响应行（含 size）→ 数据帧 → 终止帧。客户端关流即中断（下载无需清理）。
func (s *Server) download(w io.Writer, req *Request) *Error {
	rel, err := relPath(req.Path)
	if err != nil {
		return err
	}
	fi, oerr := s.root.Stat(rel)
	if oerr != nil {
		return mapOSErr("download", req.Path, oerr)
	}
	if fi.IsDir() {
		return Errf(CodeIsDir, "是目录，不是文件")
	}
	f, oerr := s.root.Open(rel)
	if oerr != nil {
		return mapOSErr("download", req.Path, oerr)
	}
	defer f.Close()
	if err := WriteLine(w, Response{Ok: true, Size: fi.Size()}); err != nil {
		return Errf(CodeOpFailed, "写响应失败：%v", err)
	}
	bufp := getBuf()
	defer putBuf(bufp)
	buf := *bufp
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := WriteFrame(w, buf[:n]); err != nil {
				return nil // 对端断了：静默收工
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return Errf(CodeOpFailed, "读文件失败：%v", rerr)
		}
	}
	if err := WriteFrame(w, nil); err != nil {
		return nil
	}
	return nil
}

// partName 生成本次上传的临时文件名：<名字>.tierpart.<8 随机 hex>（FIX-37）。
//
// 原实现是固定名 `<名字>.tierpart` + O_TRUNC——并发写同一路径会互踩（两个上传同一
// 临时文件，后提交者把先提交者的 rename 结果覆盖 / 一个取消把另一个的在途内容删掉），
// 还会**毁掉用户自己**恰好叫这个名字的文件（O_TRUNC 直接清空）。随机名 + 只删自己
// 创建的那个 = 两个问题一起消。命名保留 .tierpart 前缀（陈旧清理按它认领）。
func partName(rel string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return rel + uploadPartSuffix + "." + hex.EncodeToString(b[:]), nil
}

// cleanStaleParts 顺手回收同目录下**陈旧**的残留临时文件（FIX-36）：只清
// <目标名>.tierpart* 且 mtime 超过 stalePartAge 的（上传中断留下的；正在用的
// 一定比这个年龄新，绝不误删）。清理失败只记日志，不影响本次上传。
func (s *Server) cleanStaleParts(rel string) {
	dir := path.Dir(rel)
	base := path.Base(rel)
	d, oerr := s.root.Open(dir)
	if oerr != nil {
		return
	}
	defer d.Close()
	ents, rerr := d.ReadDir(-1)
	if rerr != nil {
		return
	}
	cutoff := time.Now().Add(-stalePartAge)
	for _, de := range ents {
		name := de.Name()
		if !strings.HasPrefix(name, base+uploadPartSuffix+".") {
			continue
		}
		fi, ierr := de.Info()
		if ierr != nil || fi.ModTime().After(cutoff) {
			continue
		}
		p := name
		if dir != "." {
			p = path.Join(dir, name)
		}
		if rerr := s.root.Remove(p); rerr == nil {
			s.logf("files: 回收陈旧临时文件 %s（超 %v 未提交）", p, stalePartAge)
		}
	}
}

// write：请求行已读 → 回 {"ok":true} 表示备好 .tierpart → 收帧 → 终止帧提交（rename）。
// 提前关流/出错 ⇒ 删 .tierpart，目标文件保持原样（原子上传，绝不留半截正式文件）。
func (s *Server) write(w io.Writer, br *bufio.Reader, req *Request) *Error {
	rel, err := relPath(req.Path)
	if err != nil {
		return err
	}
	if rel == "." {
		return Errf(CodeInvalidName, "不能写入根目录本身")
	}
	s.cleanStaleParts(rel) // 顺手清同路径的陈旧残留（FIX-36）
	part, perr := partName(rel)
	if perr != nil {
		return mapOSErr("write", req.Path, perr)
	}
	f, oerr := s.root.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if oerr != nil {
		return mapOSErr("write", req.Path, oerr)
	}
	committed := false
	defer func() {
		if !committed {
			f.Close()
			_ = s.root.Remove(part) // 取消/中断：只删自己创建的临时文件（FIX-37）
		}
	}()
	if err := WriteLine(w, Response{Ok: true}); err != nil {
		return nil // 对端已断：静默走清理
	}
	bufp := getBuf()
	defer putBuf(bufp)
	buf := *bufp
	var total int64
	for {
		n, rerr := ReadFrame(br, buf)
		if rerr != nil {
			// 未收到终止帧：取消/中断。响应写不出去也无妨。
			return Errf(CodeCanceled, "上传中断（已收到 %d 字节，已清理临时文件）", total)
		}
		if n == 0 { // 终止帧 = 提交
			break
		}
		if _, werr := f.Write(buf[:n]); werr != nil {
			return mapOSErr("write", req.Path, werr)
		}
		total += int64(n)
	}
	if err := f.Close(); err != nil {
		return mapOSErr("write", req.Path, err)
	}
	if oerr := s.renameInRoot(part, rel); oerr != nil {
		_ = s.root.Remove(part)
		return mapOSErr("write", req.Path, oerr)
	}
	committed = true
	if req.Size > 0 && req.Size != total {
		s.logf("files: 上传 %q 声明 %d 字节，实收 %d（已提交）", req.Path, req.Size, total)
	}
	return writeLineErr(w, Response{Ok: true, Size: total})
}

// renameInRoot：把临时文件改名到目标名。
//
// os.Root（go1.24.5）没有 Rename，所以这里先**经 root 打开父目录**做一次沙箱校验
// （父目录里若有指向根外的符号链接，root 会拒绝），再对拼接路径做 os.Rename：
// 目标名只允许是单段文件名（不含分隔符/`..`），临时文件与目标同目录 ⇒ 改名不可能
// 跳到父目录之外；目标本身是符号链接时，rename 会替换该链接而不是它的指向。
func (s *Server) renameInRoot(part, rel string) error {
	base := path.Base(rel)
	if base == "." || base == ".." || base == "/" || base == "" || strings.ContainsAny(base, `/\`) {
		return Errf(CodeInvalidName, "文件名不合法：%q", base)
	}
	dir := path.Dir(rel)
	if path.Dir(part) != dir {
		return Errf(CodeOpFailed, "临时文件与目标不在同一目录")
	}
	d, oerr := s.root.Open(dir)
	if oerr != nil {
		return oerr
	}
	d.Close()
	return os.Rename(filepath.Join(s.rootPath, part), filepath.Join(s.rootPath, rel))
}
