package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"strings"
)

// EncryptFile Encrypt a file
func EncryptFile(filePath, code string) error {
	key := MD5(code, 16)
	iv := MD5(code, 16)

	var buf []byte

	_, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	buf, err = os.ReadFile(filePath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	mode := cipher.NewCBCEncrypter(block, []byte(iv))

	padding := aes.BlockSize - len(buf)%aes.BlockSize
	padText := append([]byte(buf), bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, len(padText))
	mode.CryptBlocks(ciphertext, padText)

	filename := filePath + ".xu"
	o, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = o.Write(ciphertext)
	if err != nil {
		return err
	}

	return nil
}

// DecryptFile decrypts an encrypted file
func DecryptFile(filePath, code string) error {
	key := MD5(code, 16)
	iv := MD5(code, 16)

	_, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	buf, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	mode := cipher.NewCBCDecrypter(block, []byte(iv))

	var plaintext = make([]byte, len(buf))
	mode.CryptBlocks(plaintext, buf)

	// 去除 .xu 后缀获取原文件名
	filename := strings.TrimSuffix(filePath, ".xu")
	o, err := os.Create(filename)
	if err != nil {
		return err
	}

	// 去除尾部填充
	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]
	_, err = o.Write(plaintext)
	if err != nil {
		return err
	}

	return nil
}
