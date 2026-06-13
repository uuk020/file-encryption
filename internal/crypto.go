package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/schollz/progressbar/v3"
)

// EncryptFileNew encrypts a file using the new XU2\x00 chunked format with AES-256-GCM.
func EncryptFileNew(srcPath string, password string) error {
	salt, err := GenerateSalt(32)
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	params := DefaultKDFParams()
	params.Salt = salt
	key, err := DeriveKey(password, params)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source file: %w", err)
	}

	outPath := srcPath + ".xu"
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	header := FileHeader{
		Magic:         [4]byte{'X', 'U', '2', 0},
		Version:       CurrentVersion,
		SaltLen:       uint16(len(salt)),
		Salt:          salt,
		Argon2Time:    params.Time,
		Argon2Memory:  params.Memory,
		Argon2Threads: params.Threads,
		ChunkSize:     ChunkSize,
	}
	headerBytes, err := header.EncodeHeader()
	if err != nil {
		return fmt.Errorf("encode header: %w", err)
	}
	_, err = outFile.Write(headerBytes)
	if err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	bar := progressbar.DefaultBytes(srcInfo.Size(), "Encrypting file: ")

	err = encryptStream(srcFile, outFile, aead, bar)
	if err != nil {
		return err
	}

	return nil
}

func encryptStream(src io.Reader, dst io.Writer, aead cipher.AEAD, bar *progressbar.ProgressBar) error {
	buf := make([]byte, ChunkSize)

	for {
		n, err := io.ReadFull(src, buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			if err != io.ErrUnexpectedEOF {
				return fmt.Errorf("read source: %w", err)
			}
		}
		if n == 0 {
			break
		}

		var nonce [12]byte
		_, err = rand.Read(nonce[:])
		if err != nil {
			return fmt.Errorf("generate nonce: %w", err)
		}

		ciphertext := aead.Seal(nil, nonce[:], buf[:n], nil)

		chunkHeader := ChunkHeader{
			Nonce:         nonce,
			CiphertextLen: uint32(len(ciphertext)),
		}
		chunkHeaderBytes, err := chunkHeader.Encode()
		if err != nil {
			return fmt.Errorf("encode chunk header: %w", err)
		}
		_, err = dst.Write(chunkHeaderBytes)
		if err != nil {
			return fmt.Errorf("write chunk header: %w", err)
		}

		_, err = dst.Write(ciphertext)
		if err != nil {
			return fmt.Errorf("write ciphertext: %w", err)
		}

		bar.Add(n)
	}

	return nil
}

// DecryptFileNew decrypts a file using the new XU2\x00 chunked format with AES-256-GCM.
func DecryptFileNew(srcPath string, password string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source file: %w", err)
	}

	prefix := make([]byte, 4+1+2)
	_, err = io.ReadFull(srcFile, prefix)
	if err != nil {
		return fmt.Errorf("read header prefix: %w", err)
	}

	saltLen := binary.BigEndian.Uint16(prefix[5:7])
	remainingHeaderLen := int(saltLen) + 4 + 4 + 1 + 4
	remainingHeader := make([]byte, remainingHeaderLen)
	_, err = io.ReadFull(srcFile, remainingHeader)
	if err != nil {
		return fmt.Errorf("read remaining header: %w", err)
	}

	fullHeader := append(prefix, remainingHeader...)
	header, err := DecodeHeader(fullHeader)
	if err != nil {
		return fmt.Errorf("decode header: %w", err)
	}

	if string(header.Magic[:]) != MagicHeader {
		return errors.New("invalid magic header")
	}

	params := KDFParams{
		Time:    header.Argon2Time,
		Memory:  header.Argon2Memory,
		Threads: header.Argon2Threads,
		KeyLen:  32,
		Salt:    header.Salt,
	}
	key, err := DeriveKey(password, params)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	outPath := strings.TrimSuffix(srcPath, ".xu")
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	encryptedDataSize := srcInfo.Size() - int64(len(fullHeader))
	bar := progressbar.DefaultBytes(encryptedDataSize, "Decrypting file: ")

	err = decryptStream(srcFile, outFile, aead, bar)
	if err != nil {
		return err
	}

	return nil
}

func decryptStream(src io.Reader, dst io.Writer, aead cipher.AEAD, bar *progressbar.ProgressBar) error {
	chunkHeaderBuf := make([]byte, 12+4)

	for {
		_, err := io.ReadFull(src, chunkHeaderBuf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.New("authentication failed: wrong password or corrupted file")
		}

		chunkHeader, err := DecodeChunkHeader(chunkHeaderBuf)
		if err != nil {
			return errors.New("authentication failed: wrong password or corrupted file")
		}

		ciphertext := make([]byte, chunkHeader.CiphertextLen)
		_, err = io.ReadFull(src, ciphertext)
		if err != nil {
			return errors.New("authentication failed: wrong password or corrupted file")
		}

		plaintext, err := aead.Open(nil, chunkHeader.Nonce[:], ciphertext, nil)
		if err != nil {
			return errors.New("authentication failed: wrong password or corrupted file")
		}

		_, err = dst.Write(plaintext)
		if err != nil {
			return fmt.Errorf("write plaintext: %w", err)
		}

		bar.Add(16 + int(chunkHeader.CiphertextLen))
	}

	return nil
}
