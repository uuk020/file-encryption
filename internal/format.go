package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	MagicHeader     = "XU2\x00"
	CurrentVersion  = 0x01
	ChunkSize       = 4 * 1024 * 1024

	FormatNew    = "new"
	FormatLegacy = "legacy"

	magicHeaderSize = 4
)

var ErrFileTooSmall = errors.New("file too small to detect format")

type FileHeader struct {
	Magic        [4]byte
	Version      uint8
	SaltLen      uint16
	Salt         []byte
	Argon2Time   uint32
	Argon2Memory uint32
	Argon2Threads uint8
	ChunkSize    uint32
}

type ChunkHeader struct {
	Nonce         [12]byte
	CiphertextLen uint32
}

func (h *FileHeader) EncodeHeader() ([]byte, error) {
	buf := make([]byte, 4+1+2+len(h.Salt)+4+4+1+4)
	offset := 0

	copy(buf[offset:offset+4], MagicHeader)
	offset += 4

	buf[offset] = h.Version
	offset += 1

	binary.BigEndian.PutUint16(buf[offset:offset+2], h.SaltLen)
	offset += 2

	copy(buf[offset:offset+int(h.SaltLen)], h.Salt)
	offset += int(h.SaltLen)

	binary.BigEndian.PutUint32(buf[offset:offset+4], h.Argon2Time)
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:offset+4], h.Argon2Memory)
	offset += 4

	buf[offset] = h.Argon2Threads
	offset += 1

	binary.BigEndian.PutUint32(buf[offset:offset+4], h.ChunkSize)

	return buf, nil
}

func DecodeHeader(data []byte) (*FileHeader, error) {
	if len(data) < 4+1+2 {
		return nil, errors.New("data too short for header")
	}

	h := &FileHeader{}
	offset := 0

	copy(h.Magic[:], data[offset:offset+4])
	offset += 4

	if string(h.Magic[:]) != MagicHeader {
		return nil, errors.New("invalid magic header")
	}

	h.Version = data[offset]
	offset += 1

	h.SaltLen = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < 4+1+2+int(h.SaltLen)+4+4+1+4 {
		return nil, errors.New("data too short for full header")
	}

	h.Salt = make([]byte, h.SaltLen)
	copy(h.Salt, data[offset:offset+int(h.SaltLen)])
	offset += int(h.SaltLen)

	h.Argon2Time = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	h.Argon2Memory = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	h.Argon2Threads = data[offset]
	offset += 1

	h.ChunkSize = binary.BigEndian.Uint32(data[offset : offset+4])

	return h, nil
}

func (c *ChunkHeader) Encode() ([]byte, error) {
	buf := make([]byte, 12+4)
	offset := 0

	copy(buf[offset:offset+12], c.Nonce[:])
	offset += 12

	binary.BigEndian.PutUint32(buf[offset:offset+4], c.CiphertextLen)

	return buf, nil
}

func DecodeChunkHeader(data []byte) (*ChunkHeader, error) {
	if len(data) < 12+4 {
		return nil, errors.New("data too short for chunk header")
	}

	c := &ChunkHeader{}
	offset := 0

	copy(c.Nonce[:], data[offset:offset+12])
	offset += 12

	c.CiphertextLen = binary.BigEndian.Uint32(data[offset : offset+4])

	return c, nil
}

func IsNewFormat(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[:4]) == MagicHeader
}

func DetectFormat(filePath string) (string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("detect format: %s is a directory", filePath)
	}
	if info.Size() < int64(magicHeaderSize) {
		return "", ErrFileTooSmall
	}

	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	head := make([]byte, magicHeaderSize)
	n, err := io.ReadFull(f, head)
	if err != nil {
		if n == 0 {
			return "", ErrFileTooSmall
		}
		return "", err
	}

	if IsNewFormat(head[:n]) {
		return FormatNew, nil
	}
	return FormatLegacy, nil
}

func DecryptFileAuto(filePath string, password string) error {
	format, err := DetectFormat(filePath)
	if err != nil {
		return err
	}
	switch format {
	case FormatNew:
		return DecryptFileNew(filePath, password)
	case FormatLegacy:
		return DecryptFileLegacy(filePath, GenerateKey(password, 16))
	default:
		return fmt.Errorf("decrypt auto: unknown format %q", format)
	}
}