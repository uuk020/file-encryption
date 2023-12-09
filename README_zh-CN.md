# fileEncryption

这是一个使用 Go 编写的加密解密文件小工具

### 使用
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
  

### 参考项目
1. [utools-fileEncryption](https://github.com/xiaou66/utools-fileEncryption)

