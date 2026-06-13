package internal

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKDF_DefaultParams(t *testing.T) {
	params := DefaultKDFParams()
	assert.Equal(t, uint32(3), params.Time, "default time should be 3")
	assert.Equal(t, uint32(64*1024), params.Memory, "default memory should be 64MB")
	assert.Equal(t, uint8(4), params.Threads, "default threads should be 4")
	assert.Equal(t, uint32(32), params.KeyLen, "default key length should be 32")
	assert.Empty(t, params.Salt, "default salt should be empty")
}

func TestKDF_DeriveKey_SamePasswordSameSalt(t *testing.T) {
	params := KDFParams{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		Salt:    []byte("fixed-salt-for-test-1234"),
	}

	key1, err := DeriveKey("mypassword", params)
	require.NoError(t, err)
	require.Len(t, key1, int(params.KeyLen))

	key2, err := DeriveKey("mypassword", params)
	require.NoError(t, err)
	require.Len(t, key2, int(params.KeyLen))

	assert.Equal(t, key1, key2, "same password and salt should produce same key")
}

func TestKDF_DeriveKey_DifferentSalt(t *testing.T) {
	params1 := KDFParams{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		Salt:    []byte("salt-one-1234567890123"),
	}
	params2 := KDFParams{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		Salt:    []byte("salt-two-1234567890123"),
	}

	key1, err := DeriveKey("mypassword", params1)
	require.NoError(t, err)

	key2, err := DeriveKey("mypassword", params2)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "different salt should produce different key")
}

func TestKDF_GenerateSalt(t *testing.T) {
	size := 16
	salt1, err := GenerateSalt(size)
	require.NoError(t, err)
	require.Len(t, salt1, size)

	salt2, err := GenerateSalt(size)
	require.NoError(t, err)
	require.Len(t, salt2, size)

	assert.NotEqual(t, salt1, salt2, "two generated salts should be different")
}

func TestKDF_GenerateSalt_DifferentSizes(t *testing.T) {
	for _, size := range []int{8, 16, 32} {
		salt, err := GenerateSalt(size)
		require.NoError(t, err)
		assert.Len(t, salt, size)
	}
}

func TestKDF_ParamsSerialization(t *testing.T) {
	original := KDFParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		Salt:    []byte("test-salt-12345678"),
	}

	data, err := ParamsToBytes(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	decoded, err := BytesToParams(data)
	require.NoError(t, err)

	assert.Equal(t, original.Time, decoded.Time)
	assert.Equal(t, original.Memory, decoded.Memory)
	assert.Equal(t, original.Threads, decoded.Threads)
	assert.Equal(t, original.KeyLen, decoded.KeyLen)
	assert.True(t, bytes.Equal(original.Salt, decoded.Salt), "salt should round-trip correctly")
}

func TestKDF_ParamsSerialization_EmptySalt(t *testing.T) {
	original := KDFParams{
		Time:    1,
		Memory:  1024,
		Threads: 2,
		KeyLen:  16,
		Salt:    []byte{},
	}

	data, err := ParamsToBytes(original)
	require.NoError(t, err)

	decoded, err := BytesToParams(data)
	require.NoError(t, err)

	assert.Equal(t, original.Time, decoded.Time)
	assert.Equal(t, original.Memory, decoded.Memory)
	assert.Equal(t, original.Threads, decoded.Threads)
	assert.Equal(t, original.KeyLen, decoded.KeyLen)
	assert.Empty(t, decoded.Salt)
}

func TestKDF_BytesToParams_InvalidData(t *testing.T) {
	_, err := BytesToParams([]byte{0x01, 0x02})
	assert.Error(t, err, "too short data should return error")
}
