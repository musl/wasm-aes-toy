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
	"syscall/js"
)

const (
	// Version is this program's semantic version number.
	Version = `0.0.1`
)

func handleGenerate(args []js.Value) {
	if len(args) != 2 {
		log.Printf("handleGenerate needs 2 arguments but was given %d", len(args))
		return
	}

	id := args[0].String()
	length := args[1].Int()
	key := make([]byte, length)

	n, err := rand.Read(key)
	if err != nil || n != length {
		log.Printf(err.Error())
		return
	}
	b64key := base64.StdEncoding.EncodeToString(key)

	js.Global().Get("document").Call("getElementById", id).Set("value", b64key)
}

func handleDecrypt(args []js.Value) {
	if len(args) != 3 {
		log.Printf(fmt.Sprintf("handleEncrypt needs 3 arguments but was given %d", len(args)))
		return
	}

	doc := js.Global().Get("document")
	b64key := doc.Call("getElementById", args[0].String()).Get("value").String()
	ciphertext := doc.Call("getElementById", args[1].String()).Get("value").String()
	output := doc.Call("getElementById", args[2].String())

	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	plaintext, err := decrypt(key, ciphertext)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	output.Set("value", plaintext)
}

func handleEncrypt(args []js.Value) {
	if len(args) != 3 {
		log.Printf(fmt.Sprintf("handleEncrypt needs 3 arguments but was given %d", len(args)))
		return
	}

	doc := js.Global().Get("document")
	b64key := doc.Call("getElementById", args[0].String()).Get("value").String()
	plaintext := doc.Call("getElementById", args[1].String()).Get("value").String()
	output := doc.Call("getElementById", args[2].String())

	key, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	output.Set("value", ciphertext)
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

	unload := make(chan struct{})

	gcb := js.NewCallback(handleGenerate)
	defer gcb.Release()
	js.Global().Set("generate", gcb)

	ecb := js.NewCallback(handleEncrypt)
	defer ecb.Release()
	js.Global().Set("encrypt", ecb)

	dcb := js.NewCallback(handleDecrypt)
	defer dcb.Release()
	js.Global().Set("decrypt", dcb)

	bu := js.NewEventCallback(0, func(v js.Value) {
		unload <- struct{}{}
	})
	defer bu.Release()
	js.Global().Get("addEventListener").Invoke("beforeunload", bu)

	<-unload
}
