package main

import (
	"fmt"

	"github.com/freehandle/breeze/crypto"
)

var gatewayPK = crypto.PrivateKey{121, 98, 124, 72, 181, 150, 37, 34, 195, 97, 127, 65, 198, 38, 114, 116, 94, 244, 191, 249, 171, 114, 54, 232, 84, 87, 151, 146, 40, 249, 220, 89, 52, 170, 195, 171,
	223, 79, 238, 175, 43, 29, 241, 31, 238, 42, 141, 254, 202, 212, 102, 132, 0, 53, 249, 84, 179, 102, 229, 5, 205, 10, 145, 246}

func main() {
	err := <-NewServer("localhost:4100", gatewayPK.PublicKey(), 7000)
	fmt.Println(err)
}
