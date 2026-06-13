package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrent_EncryptMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	password := "concurrentpassword"

	var expectedContents [][]byte
	for i := 0; i < 12; i++ {
		content := []byte("file content " + string(rune('a'+i)))
		path := filepath.Join(dir, "file"+string(rune('a'+i))+".txt")
		require.NoError(t, os.WriteFile(path, content, 0o600))
		expectedContents = append(expectedContents, content)
	}

	result, err := EncryptDirConcurrent(dir, password, 4)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Success, 12)
	assert.Empty(t, result.Failed)
	assert.Empty(t, result.Skipped)

	for i := 0; i < 12; i++ {
		encryptedPath := filepath.Join(dir, "file"+string(rune('a'+i))+".txt.xu")
		_, err := os.Stat(encryptedPath)
		require.NoError(t, err)

		err = DecryptFileNew(encryptedPath, password)
		require.NoError(t, err)

		decryptedPath := filepath.Join(dir, "file"+string(rune('a'+i))+".txt")
		content, err := os.ReadFile(decryptedPath)
		require.NoError(t, err)
		assert.Equal(t, expectedContents[i], content)
	}
}

func TestConcurrent_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	result, err := EncryptDirConcurrent(dir, "password", 2)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Success)
	assert.Empty(t, result.Failed)
	assert.Empty(t, result.Skipped)

	result2, err := DecryptDirConcurrent(dir, "password", 2)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Empty(t, result2.Success)
	assert.Empty(t, result2.Failed)
	assert.Empty(t, result2.Skipped)
}

func TestConcurrent_EncryptMixedFiles(t *testing.T) {
	dir := t.TempDir()
	password := "password"

	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, "file"+string(rune('0'+i))+".txt")
		require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
	}

	xuFile := filepath.Join(dir, "already.xu")
	require.NoError(t, os.WriteFile(xuFile, []byte("encrypted data"), 0o600))

	result, err := EncryptDirConcurrent(dir, password, 2)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Success, 3)
	assert.Empty(t, result.Failed)
	assert.Len(t, result.Skipped, 1)
	assert.Contains(t, result.Skipped, xuFile)
}

func TestConcurrent_DecryptMixedFiles(t *testing.T) {
	dir := t.TempDir()
	password := "password"

	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, "valid"+string(rune('0'+i))+".txt")
		require.NoError(t, os.WriteFile(path, []byte("content "+string(rune('0'+i))), 0o600))
		require.NoError(t, EncryptFileNew(path, password))
	}

	plainFile := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(plainFile, []byte("plain"), 0o600))

	corrupted := filepath.Join(dir, "corrupted.xu")
	require.NoError(t, os.WriteFile(corrupted, append([]byte("XU2\x00"), []byte{0x01, 0x00, 0x10}...), 0o600))

	result, err := DecryptDirConcurrent(dir, password, 2)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Success, 3)
	assert.Len(t, result.Failed, 1)
	assert.Contains(t, result.Failed, corrupted)
	assert.Len(t, result.Skipped, 4)
	assert.Contains(t, result.Skipped, plainFile)

	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, "valid"+string(rune('0'+i))+".txt")
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, []byte("content "+string(rune('0'+i))), content)
	}
}

func TestConcurrent_DecryptPartialFailure(t *testing.T) {
	dir := t.TempDir()
	password := "password"

	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, "good"+string(rune('0'+i))+".txt")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))
		require.NoError(t, EncryptFileNew(path, password))
	}

	bad := filepath.Join(dir, "bad.xu")
	require.NoError(t, os.WriteFile(bad, append([]byte("XU2\x00"), []byte{0x01, 0x00, 0x10}...), 0o600))

	result, err := DecryptDirConcurrent(dir, password, 2)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Success, 3)
	assert.Len(t, result.Failed, 1)
	assert.Contains(t, result.Failed, bad)
	assert.Len(t, result.Skipped, 3)
	assert.Contains(t, result.Skipped, filepath.Join(dir, "good0.txt"))
	assert.Contains(t, result.Skipped, filepath.Join(dir, "good1.txt"))
	assert.Contains(t, result.Skipped, filepath.Join(dir, "good2.txt"))
}

func TestConcurrent_DefaultWorkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))

	result, err := EncryptDirConcurrent(dir, "password", 0)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Success, 1)

	result2, err := DecryptDirConcurrent(dir, "password", 0)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Len(t, result2.Success, 1)
}
