# Crypto_report_code

论文《Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds》的复现项目。

当前仓库包含两套实现：

- `src/`：Python 教学版（small-domain / large-domain / range-query / benchmark）。
- `cpp/`：C++ 重构版（模块化实现，强调结构清晰与核心思想）。

## C++ 重构版结构

```text
cpp/
  include/ore/
    common.hpp          # cmp3/编码/PRF哈希接口/小域PRP
    small_ore.hpp       # small-domain ORE API
    large_ore.hpp       # large-domain ORE API
    range_query.hpp     # RQ client/server API
  src/
    common.cpp
    small_ore.cpp
    large_ore.cpp
    range_query.cpp
  examples/demo.cpp     # 演示程序
  tests/test_main.cpp   # 端到端断言测试
  CMakeLists.txt
```

## C++ 构建与运行

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build -j
./cpp/build/ore_tests
./cpp/build/ore_demo
```

## Python 测试

```bash
python -m pytest -q
```
