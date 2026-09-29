// protocheck：手机核模块引用 homeway 协议包的冒烟（wg-native-stack tasks 1.5 判据）。
// 隔离包，不依赖模块内其它代码，可用压平 modcache 独立编译运行。
//
// 本文件只为让「无 tag 面 build 门」可编（host-registry-daemon 1.6 排除面收窄后
// 本包进包列表；实际内容全在 _test.go——测试-only 包，go build 无非测试文件会报错）。
package protocheck
