// homewayd：Homeway 后端——WG 端点 + token 签发 + 流服务（exit redial / files / 终端 / 端口转发目标）。
// 阶段 3 实现（见 tier 仓库 openspec/changes/wg-native-stack/tasks.md）。
package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("homewayd", version)
		return
	}
	fmt.Println("homewayd", version, "—— serve 尚未实现（wg-native-stack 阶段 3）")
	os.Exit(2)
}
