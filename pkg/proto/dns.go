package proto

// MaxDNSPayload53：DNS UDP 应答在隧道内可承载的报文上限（字节）。
// 由手机侧 TUN MTU（1280）扣 IP/UDP 头与隧道余量决定，两侧必须同源：
// 原本手机核写死 wgcore.maxDNSPayload53，dns-host-resolver 起挪到共享真源
// （任何一侧调 MTU，另一侧跟着改这里，否则大应答静默被隧道丢弃）。
const MaxDNSPayload53 = 1232
