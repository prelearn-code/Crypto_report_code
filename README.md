# Crypto_report_code

Lewi-Wu ORE 论文的 C++ 重构实现。

实现内容：

- `ore::SmallORE`：论文第 3.1 节 small-domain ORE，支持 `Setup / EncryptL / EncryptR / Compare / Decrypt`。
- `ore::LargeORE`：论文第 4 节 domain extension，用 block 方式支持大域整数，默认参数是 32-bit 整数，即 `blockBits=8, numBlocks=4`。
- `ore::RangeClient` / `ore::RangeServer`：论文第 5 节范围查询流程。服务端只保存右密文，客户端生成左密文查询 token，服务端用公开比较函数二分定位区间。

当前实现使用 OpenSSL `libcrypto`：

- PRF：HMAC-SHA256 截断输出。
- Random oracle 接口：SHA-256 映射到 `Z_3`。
- 小域 PRP：基于 HMAC-SHA256 驱动的 Fisher-Yates 置换，适合复现算法逻辑。

## 构建

```bash
cmake -S . -B build
cmake --build build
```

## 简单流程

```bash
./build/ore_simple_flow
```

示例流程会：

1. 创建 32-bit 大域 ORE。
2. 客户端加密数据库并上传右密文。
3. 服务端执行范围查询 `[10, 20]`。
4. 插入值 `18`，删除值 `11`。
5. 再次执行范围查询并由客户端解密返回结果。

## 模块位置

- 头文件：`include/ore/`
- 实现：`src/`
- 示例：`examples/simple_flow.cpp`

注意：该项目用于复现论文算法结构和功能流程，不包含性能评测代码。
