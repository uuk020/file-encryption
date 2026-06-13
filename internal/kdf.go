package internal

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
)

// KDFParams holds the parameters for Argon2id key derivation.
type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	Salt    []byte
}

// DefaultKDFParams returns recommended Argon2id parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
	}
}

// DeriveKey derives a key from the given password using Argon2id.
func DeriveKey(password string, params KDFParams) ([]byte, error) {
	if len(params.Salt) == 0 {
		return nil, errors.New("salt is required for key derivation")
	}
	key := argon2.IDKey(
		[]byte(password),
		params.Salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)
	return key, nil
}

// GenerateSalt generates a random salt of the specified size.
func GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("salt size must be positive")
	}
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// ParamsToBytes serializes KDFParams into a byte slice.
// Layout: Time(4) | Memory(4) | Threads(1) | KeyLen(4) | SaltLen(2) | Salt(N)
func ParamsToBytes(params KDFParams) ([]byte, error) {
	saltLen := len(params.Salt)
	if saltLen > 65535 {
		return nil, errors.New("salt too long")
	}

	buf := make([]byte, 4+4+1+4+2+saltLen)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:offset+4], params.Time)
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:offset+4], params.Memory)
	offset += 4

	buf[offset] = params.Threads
	offset += 1

	binary.BigEndian.PutUint32(buf[offset:offset+4], params.KeyLen)
	offset += 4

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(saltLen))
	offset += 2

	copy(buf[offset:offset+saltLen], params.Salt)

	return buf, nil
}

// BytesToParams deserializes KDFParams from a byte slice.
func BytesToParams(data []byte) (KDFParams, error) {
	if len(data) < 4+4+1+4+2 {
		return KDFParams{}, errors.New("data too short for params")
	}

	var params KDFParams
	offset := 0

	params.Time = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	params.Memory = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	params.Threads = data[offset]
	offset += 1

	params.KeyLen = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	saltLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(saltLen) {
		return KDFParams{}, errors.New("data too short for salt")
	}

	params.Salt = make([]byte, saltLen)
	copy(params.Salt, data[offset:offset+int(saltLen)])

	return params, nil
}
