package main

import (
	"fmt"

	"github.com/jncss/simplecipher"
)

func main() {

	key := "A un pi xic escala no li cal"

	plainText := "Proves de xifrat!!!"
	fmt.Println(plainText)

	encryptedText := simplecipher.EncryptStringB64(plainText, key)
	fmt.Println(encryptedText)

	decryptedText, _ := simplecipher.DecryptStringB64(encryptedText, key)
	fmt.Println(decryptedText)
}
