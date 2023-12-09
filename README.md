# fileEncryption

This is a file encryption and decryption tool written in Go.

[中文文档](./README_zh-CN.md)

### Usage
1. Compile the source code
    ```bash
    go build -o fileEncryption main.go
    ```
2. Encrypt a file
    ```bash
    ./fileEncryption -m=encryption -f=path/to/file -p="password"
    ```
3. Decrypt a file
    ```bash
    ./fileEncryption -m=decryption -f=encrypted/file -p="password"
    ```

### TODO
- Encrypt or decrypt all files in a folder.
- Add a progress bar.

### Reference Project
1. [utools-fileEncryption](https://github.com/xiaou66/utools-fileEncryption)
