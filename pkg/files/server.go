package files

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// 与旧 NAPI 契约对齐的默认值（app_files.go：readText 512KB / readImage 8MB）。
const (
	DefaultTextMaxBytes  = 512 * 1024
	DefaultImageMaxBytes = 8 * 1024 * 1024
	// maxInlineRead 内联载荷硬上限（防止客户端要一个超大 maxBytes 把内存吃爆）。
	maxInlineRead = 16 * 1024 * 1024
	// uploadPartSuffix 原子上传的临时后缀（死在半路只留它，绝不留正式名）。
	uploadPartSuffix = ".tierpart"
)

// Server：以某个目录为根的 files 服务（根 = 后端用户主目录，恒读写）。
type Server struct {
	root     *os.Root
	rootPath string
	logf     func(format string, args ...any)
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
	return &Server{root: r, rootPath: rootDir, logf: func(string, ...any) {}}, nil
}

// SetLogger 注入日志。
func (s *Server) SetLogger(logf func(format string, args ...any)) {
	if logf != nil {
		s.logf = logf
	}
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
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	// 问候帧恒第一个发（即使请求行非法，客户端也能先拿到 root/ver）。
	if err := WriteLine(conn, Greeting{Ok: true, Root: s.rootPath, Ver: Version, RW: true}); err != nil {
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
		return Errf("invalid_arg", "未知操作 %q", req.Op)
	}
}

func writeLineErr(w io.Writer, v any) *Error {
	if err := WriteLine(w, v); err != nil {
		return Errf("op_failed", "写响应失败：%v", err)
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
			return "", Errf("invalid_arg", "路径含非法字符")
		}
	}
	// 任何 `..` 段一律拒绝（spec：`..` 穿越必须被拒绝）。注意不能只靠 Clean：
	// path.Clean("/" + "../x") = "/x"，会把越界悄悄「洗白」成根内路径。
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", Errf("invalid_arg", "路径越界：%q", p)
		}
	}
	clean := path.Clean("/" + strings.TrimPrefix(p, "/")) // 钉成绝对再 Clean ⇒ 消掉 ..
	if clean == "/" {
		return ".", nil
	}
	rel := strings.TrimPrefix(clean, "/")
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", Errf("invalid_arg", "路径越界：%q", p)
	}
	return rel, nil
}

func mapOSErr(op, p string, err error) *Error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Errf("not_found", "%s %s：不存在", op, p)
	case errors.Is(err, os.ErrPermission):
		return Errf("permission", "%s %s：拒绝访问", op, p)
	}
	// os.Root 对逃逸（..、符号链接指向根外）返回的错误：归到 not_found，不泄漏根外信息
	if msg := err.Error(); strings.Contains(msg, "escapes from parent") || strings.Contains(msg, "outside of root") {
		return Errf("not_found", "%s %s：不存在", op, p)
	}
	return Errf("op_failed", "%s %s：%v", op, p, err)
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
		return Errf("invalid_name", "目录名不合法：%q", name)
	}
	if strings.Contains(name, "/") {
		return Errf("invalid_name", "目录名不合法：%q", name)
	}
	if _, oerr := s.root.Stat(rel); oerr == nil {
		return Errf("already_exists", "同名条目已存在")
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
		return Errf("is_dir", "是目录，不是文件")
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
		return Errf("is_dir", "是目录，不是文件")
	}
	f, oerr := s.root.Open(rel)
	if oerr != nil {
		return mapOSErr("download", req.Path, oerr)
	}
	defer f.Close()
	if err := WriteLine(w, Response{Ok: true, Size: fi.Size()}); err != nil {
		return Errf("op_failed", "写响应失败：%v", err)
	}
	buf := make([]byte, MaxChunk)
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
			return Errf("op_failed", "读文件失败：%v", rerr)
		}
	}
	if err := WriteFrame(w, nil); err != nil {
		return nil
	}
	return nil
}

// write：请求行已读 → 回 {"ok":true} 表示备好 .tierpart → 收帧 → 终止帧提交（rename）。
// 提前关流/出错 ⇒ 删 .tierpart，目标文件保持原样（原子上传，绝不留半截正式文件）。
func (s *Server) write(w io.Writer, br *bufio.Reader, req *Request) *Error {
	rel, err := relPath(req.Path)
	if err != nil {
		return err
	}
	if rel == "." {
		return Errf("invalid_name", "不能写入根目录本身")
	}
	part := rel + uploadPartSuffix
	f, oerr := s.root.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if oerr != nil {
		return mapOSErr("write", req.Path, oerr)
	}
	committed := false
	defer func() {
		if !committed {
			f.Close()
			_ = s.root.Remove(part) // 取消/中断：不留半截
		}
	}()
	if err := WriteLine(w, Response{Ok: true}); err != nil {
		return nil // 对端已断：静默走清理
	}
	buf := make([]byte, MaxChunk)
	var total int64
	for {
		n, rerr := ReadFrame(br, buf)
		if rerr != nil {
			// 未收到终止帧：取消/中断。响应写不出去也无妨。
			return Errf("canceled", "上传中断（已收到 %d 字节，已清理临时文件）", total)
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
		return Errf("invalid_name", "文件名不合法：%q", base)
	}
	dir := path.Dir(rel)
	if path.Dir(part) != dir {
		return Errf("op_failed", "临时文件与目标不在同一目录")
	}
	d, oerr := s.root.Open(dir)
	if oerr != nil {
		return oerr
	}
	d.Close()
	return os.Rename(filepath.Join(s.rootPath, part), filepath.Join(s.rootPath, rel))
}
