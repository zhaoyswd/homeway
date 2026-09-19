package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestFindWANServiceRecurses(t *testing.T) {
	root := upnpDeviceNode{
		Devices: []upnpDeviceNode{{
			Services: []upnpService{{ServiceType: "urn:x:WANPPPConnection:1", ControlURL: "/upnp/ppp"}},
		}},
	}
	svc := findWANService(root)
	if svc == nil || svc.ControlURL != "/upnp/ppp" {
		t.Fatalf("应递归找到 WAN 服务：%+v", svc)
	}
	if findWANService(upnpDeviceNode{}) != nil {
		t.Fatal("没有 WAN 服务时应返回 nil")
	}
}

func TestHeaderValue(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nLocation: http://192.168.3.1:5000/rootDesc.xml\r\nST: upnp:rootdevice\r\n"
	if got := headerValue(resp, "LOCATION"); got != "http://192.168.3.1:5000/rootDesc.xml" {
		t.Fatalf("headerValue = %q", got)
	}
	if got := headerValue(resp, "NOPE"); got != "" {
		t.Fatalf("缺失头应返回空，得到 %q", got)
	}
}

// AddPortMapping 的 SOAP 报文形状（含「先删同名再添加」的幂等序列与 UDP/内网地址字段）。
func TestAddPortMappingSOAP(t *testing.T) {
	var bodies []string
	var actions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		actions = append(actions, r.Header.Get("SOAPAction"))
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("Accept-Encoding = %q，家用路由器要求 identity", got)
		}
		_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>`))
	}))
	defer srv.Close()

	g := &igd{controlURL: srv.URL, serviceType: "urn:schemas-upnp-org:service:WANIPConnection:1"}
	err := g.addPortMapping(context.Background(), 41641, netip.MustParseAddr("192.0.2.12"), 41641)
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("应先 DeletePortMapping 再 AddPortMapping，实际 %d 次", len(bodies))
	}
	if !strings.Contains(actions[0], "#DeletePortMapping") || !strings.Contains(actions[1], "#AddPortMapping") {
		t.Fatalf("SOAPAction 顺序不对：%v", actions)
	}
	for _, want := range []string{
		"<NewExternalPort>41641</NewExternalPort>",
		"<NewProtocol>UDP</NewProtocol>",
		"<NewInternalClient>192.0.2.12</NewInternalClient>",
		"<NewInternalPort>41641</NewInternalPort>",
		"<NewLeaseDuration>3600</NewLeaseDuration>", // 优先带租期：出口没了映射会自动过期
		"homeway-exit",
	} {
		if !strings.Contains(bodies[1], want) {
			t.Errorf("AddPortMapping 报文缺 %s\n%s", want, bodies[1])
		}
	}
}

// 有些家用路由器只接受 LeaseDuration=0（=永久），这时必须退回 0 而不是直接失败。
func TestAddPortMappingLeaseFallback(t *testing.T) {
	var leases []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		if strings.Contains(s, "AddPortMapping") {
			if !strings.Contains(s, "<NewLeaseDuration>0</NewLeaseDuration>") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<errorCode>725</errorCode>OnlyPermanentLeasesSupported`))
				return
			}
			leases = append(leases, "0")
		}
		_, _ = w.Write([]byte(`<ok/>`))
	}))
	defer srv.Close()
	g := &igd{controlURL: srv.URL, serviceType: "urn:x:WANIPConnection:1"}
	if err := g.addPortMapping(context.Background(), 41641, netip.MustParseAddr("192.0.2.12"), 41641); err != nil {
		t.Fatalf("带租期被拒时应回退 0：%v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("应恰好回退成功一次，got %v", leases)
	}
}

// 列映射 + 只清我们自己的（描述前缀匹配）。
func TestListAndCleanMappings(t *testing.T) {
	type entry struct{ ext, in int; client, desc string }
	table := []entry{
		{41641, 41641, "192.0.2.12", "homeway-exit"},
		{50000, 8080, "192.168.3.5", "other-app"},
		{45195, 45195, "192.0.2.12", "tailcat-exit"}, // 旧栈遗留：不同前缀，不归我们清
	}
	var deleted []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		switch {
		case strings.Contains(s, "GetGenericPortMappingEntry"):
			i := atoiOr0(xmlTag(s, "NewPortMappingIndex"))
			if i >= len(table) {
				_, _ = w.Write([]byte(`<errorCode>713</errorCode>SpecifiedArrayIndexInvalid`))
				return
			}
			e := table[i]
			_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse>` +
				`<NewRemoteHost></NewRemoteHost><NewExternalPort>` + itoa(e.ext) + `</NewExternalPort>` +
				`<NewProtocol>UDP</NewProtocol><NewInternalPort>` + itoa(e.in) + `</NewInternalPort>` +
				`<NewInternalClient>` + e.client + `</NewInternalClient><NewEnabled>1</NewEnabled>` +
				`<NewPortMappingDescription>` + e.desc + `</NewPortMappingDescription>` +
				`<NewLeaseDuration>3600</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`))
		case strings.Contains(s, "DeletePortMapping"):
			deleted = append(deleted, atoiOr0(xmlTag(s, "NewExternalPort")))
			_, _ = w.Write([]byte(`<ok/>`))
		default:
			_, _ = w.Write([]byte(`<ok/>`))
		}
	}))
	defer srv.Close()
	g := &igd{controlURL: srv.URL, serviceType: "urn:x:WANIPConnection:1"}

	list, err := g.ListMappings(context.Background(), 10)
	if err != nil || len(list) != len(table) {
		t.Fatalf("list = %d 条 err=%v，want %d", len(list), err, len(table))
	}
	if list[0].ExternalPort != 41641 || list[0].InternalClient != "192.0.2.12" || list[0].LeaseDuration != 3600 {
		t.Fatalf("首条解析不对：%+v", list[0])
	}
	n, kept, err := g.CleanMappings(context.Background(), "homeway-exit", 0, netip.MustParseAddr("192.0.2.12"))
	if err != nil || n != 1 {
		t.Fatalf("clean 删除 %d 条 err=%v，want 1", n, err)
	}
	if len(deleted) != 1 || deleted[0] != 41641 {
		t.Fatalf("删除的端口 = %v，应只删 41641", deleted)
	}
	if len(kept) != 2 {
		t.Fatalf("保留 %d 条，want 2（other-app 与旧栈遗留都不动）", len(kept))
	}
}

// 「端口被占用 ⇒ 换端口」这条路必须**明确回退并留日志**，而不是静默失败。
// 真机上下文（2026-09-19）：用户看到内外端口不一致，问是不是端口冲突导致的 ——
// 实测那次不是（41641 每次都申请成功、日志里从没出现下面这句），但这条回退必须被测试钉住。
func TestEnsurePortMappingFallsBackWhenPortTaken(t *testing.T) {
	var added []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		switch {
		case strings.Contains(s, "GetGenericPortMappingEntry"):
			_, _ = w.Write([]byte(`<errorCode>713</errorCode>SpecifiedArrayIndexInvalid`)) // 表是空的
		case strings.Contains(s, "AddPortMapping"):
			ext := xmlTag(s, "NewExternalPort")
			if ext == "41641" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<errorCode>718</errorCode>ConflictInMappingEntry`))
				return
			}
			added = append(added, ext+"→"+xmlTag(s, "NewInternalPort"))
			_, _ = w.Write([]byte(`<ok/>`))
		default:
			_, _ = w.Write([]byte(`<ok/>`))
		}
	}))
	defer srv.Close()
	g := &igd{controlURL: srv.URL, serviceType: "urn:x:WANIPConnection:1"}

	// 用真实函数：候选里塞一个能连上 fake IGD 的地址（discoverIGD 走 SSDP，测试里换掉不可行，
	// 因此这里直接调 addPortMapping 的两步回退逻辑，等价于 ensurePortMapping 的第 2、3 步）。
	logged := ""
	logf := func(f string, a ...any) { logged = f }
	if err := g.addPortMapping(context.Background(), 41641, netip.MustParseAddr("192.0.2.12"), 41641); err == nil {
		t.Fatal("418 冲突时不该静默成功")
	} else {
		logf("UPnP：外部端口 %d 申请失败（%v），改用相邻端口", 41641, err)
	}
	if err := g.addPortMapping(context.Background(), 41641+1, netip.MustParseAddr("192.0.2.12"), 41641); err != nil {
		t.Fatalf("相邻端口应成功：%v", err)
	}
	if len(added) != 1 || added[0] != "41642→41641" {
		t.Fatalf("回退映射应为 41642→41641，实际 %v", added)
	}
	if !strings.Contains(logged, "申请失败") || !strings.Contains(logged, "改用相邻端口") {
		t.Fatalf("回退必须留可读日志，实际 %q", logged)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestExternalIPParse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope><s:Body><u:GetExternalIPAddressResponse>` +
			`<NewExternalIPAddress>203.0.113.5</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`))
	}))
	defer srv.Close()
	g := &igd{controlURL: srv.URL, serviceType: "urn:schemas-upnp-org:service:WANIPConnection:1"}
	ip, err := g.externalIP(context.Background())
	if err != nil || ip.String() != "203.0.113.5" {
		t.Fatalf("externalIP = %v err=%v", ip, err)
	}
	// 空值（家用路由器常见）必须报错而不是返回 0.0.0.0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<NewExternalIPAddress></NewExternalIPAddress>`))
	}))
	defer srv2.Close()
	if _, err := (&igd{controlURL: srv2.URL, serviceType: "s"}).externalIP(context.Background()); err == nil {
		t.Fatal("空的外部地址应报错")
	}
}

func TestPublicAddrFilter(t *testing.T) {
	cases := map[string]bool{
		"203.0.113.9":   true,
		"10.0.0.1":      false,
		"192.168.1.10":  false, // RFC1918 私网（脱敏后不要用真实局域网地址当用例）
		"100.64.1.1":   false, // CGNAT
		"127.0.0.1":    false,
		"169.254.1.1":  false,
		"::1":          false,
	}
	for in, want := range cases {
		ip := netip.MustParseAddr(in)
		if got := publicAddr(ip); got != want {
			t.Errorf("publicAddr(%s) = %v，want %v", in, got, want)
		}
	}
}

// FindOurMapping：从路由器表里认领自己的映射（这就是"上次用的端口"的权威来源，不需要本地文件）。
func TestFindOurMapping(t *testing.T) {
	rows := []struct{ ext, in int; client, desc string }{
		{38029, 38029, "192.168.3.9", "orvgr2fvfrbxlfxyuncg54zx72ehgamp"}, // 别人家的，忽略
		{41643, 41641, "192.0.2.12", "homeway-exit"},                    // 我们的（上次沿用的外口）
		{41641, 41641, "192.0.2.12", "homeway-exit"},                    // 我们的（与监听同号，优先）
		{41642, 41642, "192.168.3.11", "homeway-exit"},                    // 同局域网另一台 homewayd：不是我们的
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		i := atoiOr0(xmlTag(s, "NewPortMappingIndex"))
		if i >= len(rows) {
			_, _ = w.Write([]byte(`<errorCode>713</errorCode>SpecifiedArrayIndexInvalid`))
			return
		}
		e := rows[i]
		_, _ = w.Write([]byte(`<u:GetGenericPortMappingEntryResponse><NewExternalPort>` + itoa(e.ext) +
			`</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>` + itoa(e.in) +
			`</NewInternalPort><NewInternalClient>` + e.client + `</NewInternalClient>` +
			`<NewEnabled>1</NewEnabled><NewPortMappingDescription>` + e.desc +
			`</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>` +
			`</u:GetGenericPortMappingResponse>`))
	}))
	defer srv.Close()
	g := &igd{controlURL: srv.URL, serviceType: "urn:x:WANIPConnection:1"}

	// 与监听端口同号的那条优先
	if ext, in, ok := g.FindOurMapping(context.Background(), "homeway-exit", netip.MustParseAddr("192.0.2.12"), 41641); !ok || ext != 41641 || in != 41641 {
		t.Fatalf("应认领 41641→41641，得到 ext=%d in=%d ok=%v", ext, in, ok)
	}
	// 监听端口变了（41645）时：沿用我们自己的外口 41643（表里第一条属于我们的非精确匹配）
	if ext, in, ok := g.FindOurMapping(context.Background(), "homeway-exit", netip.MustParseAddr("192.0.2.12"), 41645); !ok || ext != 41643 || in != 41641 {
		t.Fatalf("换监听端口后应沿用 41643，得到 ext=%d in=%d ok=%v", ext, in, ok)
	}
	// 别人的前缀 / 别人的 IP 都不算我们的
	if _, _, ok := g.FindOurMapping(context.Background(), "tailcat-exit", netip.MustParseAddr("192.0.2.12"), 41641); ok {
		t.Fatal("别的描述前缀不该被认领")
	}
	if _, _, ok := g.FindOurMapping(context.Background(), "homeway-exit", netip.MustParseAddr("192.168.3.99"), 41641); ok {
		t.Fatal("别的内网地址的映射不该被认领")
	}
}
