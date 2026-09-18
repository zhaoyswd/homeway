// homeway-relay：Homeway 中继——多租户注册腿 + per-client 分配式转发 + hint 控制帧。
// 纯 stdlib。阶段 6 实现（见 tier 仓库 openspec/changes/wg-native-stack/tasks.md）。
package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("homeway-relay", version)
		return
	}
	fmt.Println("homeway-relay", version, "—— relay 尚未实现（wg-native-stack 阶段 6）")
	os.Exit(2)
}
