# fileEncryption

这是一个使用 Go 编写的加密解密文件小工具

### 使用
1. 编译代码
    ```bash
    go build -o fileEncryption main.go
    ```
2. 加密文件
    ```bash
    ./fileEncryption -m=encryption -f=path/to/file -p="password"
    ```
3. 解密文件
    ```bash
    ./fileEncryption -m=decryption -f=encrypted/file -p="password"

### 待办事项
1. 遍历文件夹下所有文件加密或解密
2. 增加进度条


### 参考项目
1. [utools-fileEncryption](https://github.com/xiaou66/utools-fileEncryption)

