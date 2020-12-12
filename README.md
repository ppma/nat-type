[1]: https://tools.ietf.org/images/rfc.png
[2]: https://img.shields.io/badge/license-MIT-blue.svg
[3]: LICENSE

[![MIT licensed][2]][3]

## 介绍

[nat-type](https://github.com/ppma/nat-type) 是 [RFC 3489][1]
的go实现，从 [NatTypeDetector](https://github.com/cdnbye/NatTypeDetector) 移植而来。
代码写得烂，思想跟不上，就这样了

## 使用

```go
package main

import (
	"fmt"
	"github.com/ppma/nat-type"
)

const (
	STUN_SERVER = "stun.miwifi.com"
	STUN_PORT   = 3478
)

func main() {
	localAddr := fmt.Sprintf("%s:%d", "192.168.101.3", STUN_PORT)
	stunAddr := fmt.Sprintf("%s:%d", STUN_SERVER, STUN_PORT)
	result, err := stun.Query(stunAddr, localAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Nat type: ", stun.result.GetNatType())
	fmt.Println("Public IP: ", stun.result.GetIpAddr())
}
```