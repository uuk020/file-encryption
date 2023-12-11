# fileEncryption

This is a file encryption and decryption tool written in Go. It can also decrypt files encrypted with utools-fileEncryption.

[中文文档](./README_zh-CN.md)

### Usage
1. Compile the code
    ```bash
    go build -o fileEncryption main.go
    ```
2. Encrypt a folder or file
    ```bash
    ./fileEncryption -m=encryption -d=path -p=password
    ```
    or
    ```bash
    ./fileEncryption -m=encryption -f=path/to/file -p=password
    ```
    
3. Decrypt a folder or file
    ```bash
    ./fileEncryption -m=decryption -d=path -p=password
    ```
    or
    ```bash
    ./fileEncryption -m=decryption -f=path/to/file -p=password
    ```

### TODO List
1. ~~Traverse all files in a folder for encryption or decryption~~
2. Add a progress bar


### Reference Project
1. [utools-fileEncryption](https://github.com/xiaou66/utools-fileEncryption)