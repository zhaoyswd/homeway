package dns

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"
)

// Upstreams：/etc/resolv.conf nameserver 列表的跟随器（design D5）。
//
// 每次 List() 触发 mtime 检查（1s 节流）：变了就重新解析并替换；读取或解析
// 失败保留 last-good 列表继续服务（规避 stdlib noReload 类「瞬坏永久卡」问题，
// 也与 cgo/pure 构建形态无关）。跟随语义是主机的**主解析器**——hosts/mDNS/
// scoped resolver 不在范围。
type Upstreams struct {
	path string

	mu        sync.Mutex
	lastCheck time.Time
	mtime     time.Time
	list      []string
}

// checkInterval：mtime 检查节流（跟随粒度秒级，spec「上游跟随主机系统解析」）。
const checkInterval = time.Second

// NewUpstreams 初次加载 resolv.conf。**空列表不报错**（review M6）：容器刚起、
// systemd-resolved 未就绪时 resolv.conf 可能暂时为空/不可读——若此时失败，
// 代答整个生命周期都不会再尝试（手机侧已声明隧道 IP 为 DNS，后果全断）。
// 空表 + List() 的周期重试（见下）覆盖这个窗口；期间查询自然落到兜底上游。
func NewUpstreams(path string) (*Upstreams, error) {
	u := &Upstreams{path: path, lastCheck: time.Now()}
	if fi, err := os.Stat(path); err == nil {
		if list := parseResolvNameservers(path); len(list) > 0 {
			u.list, u.mtime = list, fi.ModTime()
		}
	}
	return u, nil
}

// List 返回当前 nameserver 列表（host 形式，resolv.conf 的 nameserver 都是 IP）。
// 空表时每个节流窗口都强制重读（不依赖 mtime——启动竞态里文件可能原地出现）；
// 非空时按 mtime 变更跟随，读取/解析失败保留 last-good。
func (u *Upstreams) List() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	if now.Sub(u.lastCheck) < checkInterval {
		return u.list
	}
	u.lastCheck = now
	if len(u.list) > 0 {
		fi, err := os.Stat(u.path)
		if err != nil || fi.ModTime().Equal(u.mtime) {
			return u.list // 读取失败保留 last-good
		}
	}
	if list := parseResolvNameservers(u.path); len(list) > 0 {
		if fi, err := os.Stat(u.path); err == nil {
			u.list, u.mtime = list, fi.ModTime()
		}
	}
	return u.list
}

// parseResolvNameservers 逐行取 nameserver 项（忽略注释/其它指令）。返回空
// 列表 = 文件无有效上游（调用方保留 last-good）。
func parseResolvNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && fields[1] != "" {
			out = append(out, fields[1])
		}
	}
	return out
}
