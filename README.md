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

## 核心思想

Lewi-Wu ORE 采用 left/right ciphertext 框架：

- 左密文 `EncryptL(x)`：由客户端生成，用作查询或比较 token。它不包含完整的比较表，只包含一个置换后的位置 `h`，以及用于解开该位置 mask 的密钥材料 `keyMaterial`。
- 右密文 `EncryptR(y)`：由客户端生成并存储到服务端。它包含 nonce 和一个 masked 比较结果数组。数组中每个位置对应一个可能的明文值与 `y` 的比较结果。
- 公开比较 `Compare(ctL, ctR)`：服务端只需要左密文和右密文，就能得到 `x` 与 `y` 的大小关系，但单独保存的右密文不直接暴露排序关系。

比较结果用 `Z_3` 表示：

```cpp
0: x == y
1: x < y
2: x > y
```

## 小域 ORE 实现

小域方案位于 `src/small_ore.cpp`。它直接对应论文第 3.1 节。

### 左加密 `EncryptL`

左加密先用 PRP 将明文 `x` 映射到隐藏位置 `h = pi(x)`，再用 PRF 派生该位置的密钥材料：

```cpp
SmallLeftCiphertext SmallORE::encryptLeft(uint32_t x) const {
    SmallDomainPrp prp(key_.prpSeed, key_.domainSize);
    uint32_t h = prp.permute(x);
    Bytes material = hmacSha256(key_.prfKey, encodeInteger(h), 16);
    return SmallLeftCiphertext{material, h};
}
```

对应论文公式：

```text
ctL = (F(k, pi(x)), pi(x))
```

### 右加密 `EncryptR`

右加密会为小域中的每个候选值预计算比较结果。为了不泄露这些比较值，代码用 `hashToZ3(material, nonce)` 生成 mask，并在模 3 空间中隐藏比较结果：

```cpp
SmallRightCiphertext SmallORE::encryptRight(uint32_t y) const {
    SmallDomainPrp prp(key_.prpSeed, key_.domainSize);
    Bytes nonce = randomBytes(16);
    std::vector<uint8_t> values;

    for (uint32_t i = 0; i < key_.domainSize; ++i) {
        uint32_t candidate = prp.invert(i);
        uint8_t plainCmp = cmp3(candidate, y);
        Bytes material = hmacSha256(key_.prfKey, encodeInteger(i), 16);
        uint8_t mask = hashToZ3(material, nonce);
        values.push_back(static_cast<uint8_t>((plainCmp + mask) % 3));
    }

    return SmallRightCiphertext{nonce, values};
}
```

对应论文公式：

```text
vi = cmp(pi^-1(i), y) + H(F(k, i), r) mod 3
ctR = (r, v1, ..., vN)
```

### 公开比较 `Compare`

比较时，左密文提供位置 `h` 和密钥材料，服务端从右密文数组中取出 `values[h]`，再减去同一个 mask：

```cpp
uint8_t SmallORE::compare(const SmallLeftCiphertext& left,
                          const SmallRightCiphertext& right) {
    uint8_t value = right.values[left.h];
    uint8_t mask = hashToZ3(left.keyMaterial, right.nonce);
    return static_cast<uint8_t>((value + 3 - mask) % 3);
}
```

因此：

```text
Compare(EncryptL(x), EncryptR(y)) = cmp(x, y)
```

## 大域 ORE 实现

大域方案位于 `src/large_ore.cpp`，对应论文第 4 节 domain extension。

默认参数为：

```cpp
ore::LargeORE ore = ore::LargeORE::setup(8, 4);
```

这表示把 32-bit 整数拆成 4 个 8-bit block。每个 block 的取值范围是 `[0, 256)`，所以每一层可以复用小域 ORE 的思想。

大域左加密的核心流程：

```cpp
for (uint32_t i = 0; i < key_.numBlocks; ++i) {
    Bytes prpSeed = hmacSha256(
        key_.k2,
        encodePrfInput("large.prp.prefix", key_.blockBits, key_.numBlocks, prefix),
        16
    );
    SmallDomainPrp prp(prpSeed, base);
    uint32_t h = prp.permute(blocks[i]);

    Bytes material = hmacSha256(
        key_.k1,
        encodePrfInput("large.compare.key", key_.blockBits, key_.numBlocks, prefix, h),
        16
    );

    out.push_back(LargeLeftBlock{material, h});
    prefix.push_back(blocks[i]);
}
```

大域右加密的核心流程：

```cpp
for (uint32_t i = 0; i < key_.numBlocks; ++i) {
    Bytes prpSeed = hmacSha256(
        key_.k2,
        encodePrfInput("large.prp.prefix", key_.blockBits, key_.numBlocks, prefix),
        16
    );
    SmallDomainPrp prp(prpSeed, base);

    std::vector<uint8_t> values;
    for (uint32_t j = 0; j < base; ++j) {
        uint32_t candidate = prp.invert(j);
        uint8_t plainCmp = cmp3(candidate, blocks[i]);

        Bytes material = hmacSha256(
            key_.k1,
            encodePrfInput("large.compare.key", key_.blockBits, key_.numBlocks, prefix, j),
            16
        );

        uint8_t mask = hashToZ3(material, nonce);
        values.push_back(static_cast<uint8_t>((plainCmp + mask) % 3));
    }

    outBlocks.push_back(std::move(values));
    prefix.push_back(blocks[i]);
}
```

这里的 `prefix` 是大域扩展的关键：第 `i` 个 block 使用前 `i - 1` 个 block 作为 PRF/PRP 输入的一部分，从而形成前缀相关的小域实例。比较时从高位 block 到低位 block 依次比较，遇到第一个非 0 比较结果就返回：

```cpp
for (uint32_t i = 0; i < left.numBlocks; ++i) {
    uint8_t value = right.blocks[i][left.blocks[i].h];
    uint8_t mask = hashToZ3(left.blocks[i].keyMaterial, right.nonce);
    uint8_t plainCmp = static_cast<uint8_t>((value + 3 - mask) % 3);
    if (plainCmp != 0) {
        return plainCmp;
    }
}
return 0;
```

## 范围查询流程

范围查询位于 `src/range_query.cpp`，对应论文第 5 节。

服务端只保存右密文：

```cpp
out.push_back(StoredRecord{record.id, ore_.encryptRight(record.value)});
```

客户端查询 `[lower, upper]` 时生成两个左密文：

```cpp
return RangeToken{ore_.encryptLeft(lower), ore_.encryptLeft(upper)};
```

服务端使用公开比较函数在右密文数组上二分查找边界：

```cpp
std::size_t first = lowerBound(token.lower);
std::size_t last = upperBound(token.upper);
return std::vector<StoredRecord>(records_.begin() + first, records_.begin() + last);
```

整体流程是：

1. 客户端对数据库值生成右密文并排序上传。
2. 服务端保存排序后的右密文列表。
3. 查询时客户端发送范围边界的左密文。
4. 服务端用 `Compare(left, right)` 二分定位区间。
5. 服务端返回命中的右密文，客户端本地解密得到明文结果。

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
