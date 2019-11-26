package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"strings"
	"syscall/js"
	"testing"
	"time"
)

const (
	// Version is this program's semantic version number.
	Version = `0.0.1`

	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randString(n int) string {
	src := mrand.NewSource(time.Now().UnixNano())
	sb := strings.Builder{}
	sb.Grow(n)

	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

func handleBenchmark(this js.Value, args []js.Value) interface{} {

	// Demo setting flags
	// testing.Init()
	// flag.Set("test.benchtime", "1000000x")
	// flag.Parse()

	encryptBenchmark := func(keyLength, textLength int) func(b *testing.B) {
		key := generateKey(keyLength)
		plainText := randString(textLength)
		return func(b *testing.B) {
			_, err := encrypt(key, plainText)
			if err != nil {
				b.FailNow()
			}
		}
	}

	decryptBenchmark := func(keyLength, textLength int) func(b *testing.B) {
		key := generateKey(keyLength)
		plainText := randString(textLength)
		cipherText, _ := encrypt(key, plainText)

		return func(b *testing.B) {
			_, err := decrypt(key, cipherText)
			if err != nil {
				b.FailNow()
			}
		}
	}

	var results strings.Builder
	fmt.Fprintln(&results, "Benchmark Results:")

	textLength := 2 * 1024 * 1024
	keyLengths := []int{16, 24, 32}
	for _, keyLength := range keyLengths {
		er := testing.Benchmark(encryptBenchmark(keyLength, textLength))
		dr := testing.Benchmark(decryptBenchmark(keyLength, textLength))
		fmt.Fprintf(
			&results,
			"%d bit encrypt: %s\n%d bit decrypt: %s\n",
			keyLength*8,
			er.String(),
			keyLength*8,
			dr.String(),
		)
	}

	js.Global().Call("alert", results.String())
	return nil
}

func generateKey(length int) []byte {
	key := make([]byte, length)

	n, err := rand.Read(key)
	if err != nil || n != length {
		log.Printf(err.Error())
		return nil
	}

	return key
}

func handleGenerate(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		log.Printf("handleGenerate needs 2 arguments but was given %d", len(args))
		return nil
	}

	id := args[0].String()
	length := args[1].Int()
	key := generateKey(length)
	b64key := base64.StdEncoding.EncodeToString(key)

	js.Global().Get("document").Call("getElementById", id).Set("value", b64key)

	return nil
}

func handleDecrypt(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		log.Printf(fmt.Sprintf("handleEncrypt needs 3 arguments but was given %d", len(args)))
		return nil
	}

	doc := js.Global().Get("document")
	b64key := doc.Call("getElementById", args[0].String()).Get("value").String()
	ciphertext := doc.Call("getElementById", args[1].String()).Get("value").String()
	output := doc.Call("getElementById", args[2].String())

	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}

	plaintext, err := decrypt(key, ciphertext)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}

	output.Set("value", plaintext)

	return nil
}

func handleEncrypt(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		log.Printf(fmt.Sprintf("handleEncrypt needs 3 arguments but was given %d", len(args)))
		return nil
	}

	doc := js.Global().Get("document")
	b64key := doc.Call("getElementById", args[0].String()).Get("value").String()
	plaintext := doc.Call("getElementById", args[1].String()).Get("value").String()
	output := doc.Call("getElementById", args[2].String())

	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}

	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}

	output.Set("value", ciphertext)

	return nil
}

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func main() {
	log.Printf("AES Toy Version v%s", Version)

	gcb := js.FuncOf(handleGenerate)
	defer gcb.Release()
	js.Global().Set("generate", gcb)

	ecb := js.FuncOf(handleEncrypt)
	defer ecb.Release()
	js.Global().Set("encrypt", ecb)

	dcb := js.FuncOf(handleDecrypt)
	defer dcb.Release()
	js.Global().Set("decrypt", dcb)

	bcb := js.FuncOf(handleBenchmark)
	defer bcb.Release()
	js.Global().Set("benchmark", bcb)

	/*
	* Wait for the page to unload.
	 */
	unload := make(chan struct{})
	bu := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		unload <- struct{}{}
		return nil
	})
	defer bu.Release()
	js.Global().Get("addEventListener").Invoke("beforeunload", bu)
	<-unload
}
