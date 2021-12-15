package simplecipher

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"time"
)

// IVLEN llargada del vector d'inicialitzacio
const IVLEN = 4

// fnv1_64 Hash FNV1_64
func Fnv1_64(data []byte) []byte {
	var hash uint64
	r := make([]byte, 8)
	hash = 14695981039346656037
	for _, c := range data {
		hash = hash * 1099511628211
		hash = hash ^ uint64(c)
	}
	binary.BigEndian.PutUint64(r, hash)

	//fmt.Println(hex.EncodeToString(r))
	return r
}

// Encrypt Xifrat
func Encrypt(data, key []byte) []byte {
	k := Fnv1_64(key)
	iv := make([]byte, IVLEN)
	l := len(k)
	m := len(k) >> 1

	result := make([]byte, len(data)+IVLEN)
	rand.Seed(time.Now().UTC().UnixNano())
	for n := 0; n < IVLEN; n++ {
		iv[n] = byte(rand.Intn(256))
	}
	copy(result, iv)

	for n, d := range data {
		c := d ^ iv[n%IVLEN]
		c = (c + k[n%l]) & 0xff
		c = c ^ k[n%l]
		c = (c + k[(n+m)%l]) & 0xff
		c = c ^ k[(n+m)%l]
		result[n+IVLEN] = c
		iv[n%IVLEN] = c
	}

	return result
}

// Decrypt Desxifrat
func Decrypt(data, key []byte) []byte {
	k := Fnv1_64(key)
	l := len(k)
	m := len(k) >> 1
	result := make([]byte, len(data)-IVLEN)

	iv := data[0:IVLEN]
	for n, d := range data[IVLEN:] {
		t := d ^ k[(n+m)%l]
		t = (t - k[(n+m)%l]) & 0xff
		t = t ^ k[n%l]
		t = (t - k[n%l]) & 0xff
		t = t ^ iv[n%IVLEN]
		result[n] = t
		iv[n%IVLEN] = d
	}

	return result
}

// EncryptString Xifrar string
func EncryptString(text, key string) string {
	encryptedText := Encrypt([]byte(text), []byte(key))

	return hex.EncodeToString(encryptedText)
}

// DecryptString Desxifrar string
func DecryptString(text, key string) (string, error) {
	data, err := hex.DecodeString(text)
	if err == nil {
		return string(Decrypt(data, []byte(key))), nil
	}

	return "", err
}
