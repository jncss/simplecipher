package main

import (
	"fmt"

	"github.com/jncss/simplecipher"
)

func main() {

	key := "func main()"

	plainText := "Proves de xifrat!!!"
	fmt.Println(plainText)

	encryptedText := simplecipher.EncryptStringB64(plainText, key)
	fmt.Println(encryptedText)

	decryptedText, _ := simplecipher.DecryptStringB64(encryptedText, key)
	fmt.Println(decryptedText)

	fmt.Println(simplecipher.DecryptString("dfa49019e2fe40e1fdc93fcafb3171a8f4bfec8dd4453166", "func main()"))
}
