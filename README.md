# Crypto_report_code

教学版 ORE 复现项目（第一阶段：small-domain ORE）。

## 已完成

- `src/common/`：比较编码、序列化、PRF/哈希工具、小域 PRP（seeded Fisher-Yates）
- `src/ore_small/`：`Setup / EncryptL / EncryptR / Compare / Decrypt`
- `tests/test_small_ore.py`：正确性与解密测试

## 运行测试

```bash
python -m pytest -q
```

## small-domain 快速示例

```python
from ore_small.scheme import SmallDomainORE

ore = SmallDomainORE.setup(domain_size=32)
ct_l = ore.encrypt_left(7)
ct_r = ore.encrypt_right(11)
print(ore.compare(ct_l, ct_r))  # 1, because 7 < 11
print(ore.decrypt(ct_r))        # 11
```
