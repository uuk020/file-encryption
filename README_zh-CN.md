# fileEncryption

这是一个使用 Go 编写的加密解密文件小工具。新版本使用 **AES-256-GCM** 加密和 **Argon2id** 密钥派生，同时保留对旧版 `.xu` 格式（包括 utools-fileEncryption 加密文件）的解密兼容性。

### 功能特性

- **新安全格式**：AES-256-GCM 加密 + Argon2id 密钥派生，随机盐值，每块独立随机 nonce
- **向后兼容**：可解密旧版 `.xu` 文件（AES-CBC + MD5 密钥派生）
- **流式加密**：4MB 分块处理，支持大文件不载入内存
- **并发目录处理**：多线程加密/解密目录内文件
- **交互式密码输入**：省略 `-p` 时安全地提示输入密码（无回显）
- **密码确认**：交互式加密时两次输入确认密码
- **自动格式检测**：通过文件头自动识别新/旧格式
- **解密后自动删除加密文件**：解密成功后自动删除源 `.xu` 加密文件
- **删除原文件**：`--delete` / `-r` 标志在加密后删除原始文件
- **进度条**：文件操作进度可视化

### 使用

#### 编译

```bash
go build -o fileEncryption main.go
```

#### 加密文件

```bash
./fileEncryption -m encrypt -f path/to/file -p password
```

#### 解密文件

```bash
./fileEncryption -m decrypt -f path/to/file.xu -p password
```

#### 加密目录

```bash
./fileEncryption -m encrypt -d path/to/dir -p password
```

#### 解密目录

```bash
./fileEncryption -m decrypt -d path/to/dir -p password
```

#### 交互模式（不在命令行输入密码）

```bash
./fileEncryption -m encrypt -f path/to/file
# 提示输入密码（无回显）
```

#### 加密后删除原文件

```bash
./fileEncryption -m encrypt -f path/to/file -p password --delete
```

#### 解密文件（加密文件将自动删除）

```bash
./fileEncryption -m decrypt -f path/to/file.xu -p password
```

### CLI 参数

| 参数 | 说明 |
|------|------|
| `-m` | 模式：`encrypt` / `encryption` 或 `decrypt` / `decryption` |
| `-p` | 加密/解密密码 |
| `-f` | 单文件路径 |
| `-d` | 目录路径 |
| `-r` / `--delete` | 加密后删除原文件 |


### 参考项目

1. [utools-fileEncryption](https://github.com/xiaou66/utools-fileEncryption)

### 许可证

MIT License
