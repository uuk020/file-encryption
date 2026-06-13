# fileEncryption

This is a file encryption and decryption tool written in Go. It uses **AES-256-GCM** with **Argon2id** key derivation for the new encryption format, and retains backward compatibility to decrypt files encrypted with the legacy `.xu` format (including those from utools-fileEncryption).

[中文文档](./README_zh-CN.md)

## Features

- **New Secure Format**: AES-256-GCM encryption with Argon2id key derivation, random salt and per-chunk nonce
- **Backward Compatibility**: Can decrypt legacy `.xu` files (AES-CBC + MD5 key derivation)
- **Streaming Encryption**: 4MB chunked processing, supports large files without loading into memory
- **Concurrent Directory Processing**: Multi-threaded encryption/decryption of directories
- **Interactive Password Input**: Secure no-echo password prompt when `-p` is omitted
- **Password Confirmation**: Encrypting interactively prompts twice for password verification
- **Auto Format Detection**: Automatically detects new vs legacy format via file header
- **Delete Encrypted Files After Decryption**: Decrypted files automatically remove the source `.xu` file
- **Delete Original Files**: `--delete` / `-r` flag to remove source files after encryption
- **Progress Bar**: Visual progress indicator for file operations

## Usage

### Compile

```bash
go build -o fileEncryption main.go
```

### Encrypt a file

```bash
./fileEncryption -m encrypt -f path/to/file -p password
```

### Decrypt a file

```bash
./fileEncryption -m decrypt -f path/to/file.xu -p password
```

### Encrypt a directory

```bash
./fileEncryption -m encrypt -d path/to/dir -p password
```

### Decrypt a directory

```bash
./fileEncryption -m decrypt -d path/to/dir -p password
```

### Interactive mode (no password on command line)

```bash
./fileEncryption -m encrypt -f path/to/file
# Prompts for password (no echo)
```

### Delete original files after encryption

```bash
./fileEncryption -m encrypt -f path/to/file -p password --delete
```

### Decrypt a file (encrypted file will be deleted automatically)

```bash
./fileEncryption -m decrypt -f path/to/file.xu -p password
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `-m` | Mode: `encrypt` / `encryption` or `decrypt` / `decryption` |
| `-p` | Password for encryption/decryption |
| `-f` | Single file path |
| `-d` | Directory path |
| `-r` / `--delete` | Delete original files after encryption |


## Reference Projects

1. [utools-fileEncryption](https://github.com/xiaou66/utools-fileEncryption)

## License

MIT License
