//go:build cshared

package main

// c-shared 要求存在 main，但不作为入口执行（库模式）。
func main() {}
