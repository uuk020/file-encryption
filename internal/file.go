package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"strings"
)

// EncryptFile Encrypt a file
func EncryptFile(filePath string, key []byte) error {
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
	mode := cipher.NewCBCEncrypter(block, []byte(key))

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

// EncryptDir encrypts all files in a directory
func EncryptDir(path string, key []byte) error {
	// 遍历目录
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".xu") {
			return nil
		}
		err = EncryptFile(path, key)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// DecryptFile decrypts an encrypted file
func DecryptFile(filePath string, key []byte) error {
	_, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	buf, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	mode := cipher.NewCBCDecrypter(block, key)

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

// DecryptDir decrypts all encrypted files in a directory
func DecryptDir(path string, key []byte) error {
	// 遍历目录
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".xu") {
			return nil
		}
		err = DecryptFile(path, key)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
