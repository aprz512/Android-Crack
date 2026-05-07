# scripts/

项目辅助脚本。

## fn_audit.py — IDA decompile 函数预处理/评分工具

从 N 个反编译 C 文件里筛出值得人工审查的高价值目标。把 23k 函数降到 ~100 个核心检测点。

### 快速使用

```bash
# ACE SDK (libanogs.so) 默认预设，地址上限排除 libstdc++，最低分 5 分
python3 scripts/fn_audit.py \
    unidbg-android/src/test/resources/arknights/ida_export/decompile \
    --preset ace --addr-max 0x4FC000 --min-score 5 \
    --out /tmp/audit.txt
```

输出（stderr 统计 + stdout/文件排序结果）：
```
[fn_audit] scanned 23821 files:
  - too small (<280B):   8035
  - thunk / trivial:     1311
  - stdlib noise:        28
  - addr >= 0x4fc000:    621
  = scored (5+):         103

   1.   61  4A14AC.c    inline_hook×2,set_inline_hook×1,sub_4A14AC×2,...
   2.   27  1C5B20.c    loc_1C2990×3,emulator×1,sub_1C5B20×2
   3.   24  26D344.c    ptrace×2,PTRACE_ATTACH×1,PTRACE_DETACH×1,waitpid×1
   ...
```

### 参数

| 参数 | 说明 |
|------|------|
| `decompile_dir` | 必填。IDA 导出的 `decompile/` 目录 |
| `--preset {ace,generic,custom}` | 关键词预设。默认 `ace` |
| `--keywords-file FILE.json` | 与 `--preset custom` 配合，格式 `{"keyword": weight}` |
| `--addr-max 0xNNNN` | 排除文件名地址 ≥ 此值（libstdc++/libc++abi 内嵌） |
| `--min-score N` | 最低分数（默认 1） |
| `--top N` | 只输出 Top N |
| `--exclude-file FILE` | 已分析函数列表（每行一个 hex 地址或文件名），排除掉 |
| `--out FILE` | 输出到文件（默认 stdout） |

### 算法

4 层过滤 + 评分：

1. **大小过滤**：< 280 字节（thunk / 1-line wrapper）
2. **thunk 标记**：IDA 标注 `// attributes: thunk` 的函数
3. **有效代码行数**：去注释 + 去花括号 + 去变量声明后 < 5 行
4. **stdlib 噪音启发式**：
   - 字串含 `__cxa_` / `libc++abi` / `cxa_personality` / `__assert2` 等
   - `abort()×≥3` 配 `realloc()` = C++ 容器 OOM 分支
   - 地址 ≥ `--addr-max` 的高地址区段
5. **关键词评分**：每命中 = `weight × min(count, 3)`（cap 3 防刷分）

### 复用到新 APK

针对新的目标 SO：

1. 先用 `--preset generic` 粗扫，看 Top 30
2. 从结果里挑几个明显核心函数，开始人工分析
3. 分析过程中收集该 SDK 的**内部符号/魔数/字符串**特征
4. 把这些特征加入 `--keywords-file`，提高后续扫描精度（ACE 的 `sub_4A14AC` / `loc_1C2990` / `BEEF` 就是这么来的）
5. 每发现新检测类型，补关键词，重新跑，迭代 2-3 次

### 关键词权重参考

- **5** — 决定性信号（`ptrace`, `zygisk`, `TracerPid`, SDK 特有符号）
- **4** — 高价值（`prctl`, `inotify`, `socket`, `RegisterNatives`）
- **3** — 中等（`/proc/`, `FindClass`, `crc`, `Assert`）
- **2** — 弱信号（`clock_gettime`, 解密 wrapper 调用）
- **1** — 噪音级（`root`, `toString`, `jni`）

## keywords_sample.json

极简自定义示例：只匹配 ptrace 家族。用于派生你自己的预设。
