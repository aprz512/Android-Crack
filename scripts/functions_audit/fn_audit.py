#!/usr/bin/env python3
"""
IDA decompile function audit — 预处理筛选工具

从 N 个反编译 C 文件里筛出高价值审查目标。把 23k 函数降到 ~100 个。

用法:
    python scripts/fn_audit.py <decompile_dir> [--out <outfile>] [--preset <name>]

预设:
    ace       — ACE Anti-Cheat SDK (libanogs.so) 关键词集
    generic   — 通用反调试/反作弊关键词
    custom    — 从 --keywords-file 加载

示例:
    python scripts/fn_audit.py unidbg-android/src/test/resources/arknights/ida_export/decompile \
        --preset ace --out /tmp/audit.txt
    python scripts/fn_audit.py <dir> --preset custom --keywords-file mine.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ==================== 污染过滤 ====================

# 见到以下强 marker 之一 → score 直接归零（stdlib / C++ EH 的强信号）
# 注意：__stack_chk_fail 是普通业务函数开启栈保护后的常见尾调用，不能作为一票否决信号。
STDLIB_MARKERS = frozenset({
    'cxa_personality', 'libc++abi', '__cxa_', 'libcxx',
    '_Unwind_', '__assert2',
    'std::__',
})


def is_stdlib_noise(body: str) -> bool:
    """启发式判定为 stdlib / 运行时代码"""
    if any(m in body for m in STDLIB_MARKERS):
        return True
    # 大量 abort() 配 realloc() = C++ 容器 OOM 分支
    if body.count('abort()') >= 3 and body.count('realloc(') >= 1:
        return True
    return False


# ==================== Trivial 过滤 ====================

MIN_FILE_SIZE = 280  # 字节；小于此值几乎都是 thunk / 1-line wrapper
MIN_CODE_LINES = 5   # 有效代码行数下限
THUNK_MARKER = '// attributes: thunk'

# 匹配单行变量声明: "T name;", "T *name;", "T* name[8];", "_QWORD v5;"
VAR_DECL_RE = re.compile(r'^\s*\w+\s*\*?\s*\w+\s*(?:\[[^\]]*\])?\s*;\s*$')


def count_effective_lines(body: str) -> int:
    """去注释、空行、纯花括号、单纯变量声明后剩余的代码行数"""
    count = 0
    in_block_comment = False
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        # 粗略处理块注释
        if in_block_comment:
            if '*/' in s:
                in_block_comment = False
            continue
        if s.startswith('/*'):
            if '*/' not in s:
                in_block_comment = True
            continue
        if s.startswith('//'):
            continue
        if s in ('{', '}', '};', '{};'):
            continue
        if VAR_DECL_RE.match(s):
            continue
        count += 1
    return count


def is_trivial(path: Path, body: str) -> bool:
    if path.stat().st_size < MIN_FILE_SIZE:
        return True
    if THUNK_MARKER in body:
        return True
    if count_effective_lines(body) < MIN_CODE_LINES:
        return True
    return False


# ==================== 关键词预设 ====================

KEYWORDS_ACE: dict[str, int] = {
    # 权重 5 — 决定性信号
    'ptrace': 5, 'seccomp': 5, 'readlink': 3, 'inotify': 4,
    '/proc/self/maps': 5, '/proc/self/status': 5, '/proc/kallsyms': 5,
    '/proc/modules': 5, '/proc/cpuinfo': 5, '/proc/self/exe': 4,
    '/proc/self/cmdline': 4,
    'zygisk': 5, 'magisk': 5, 'frida': 5, 'xposed': 5, 'virapp': 5,
    'inline_hook': 5, 'set_inline_hook': 5, 'fc_thread_start': 5,
    'BEEF': 5, 'DEADBEEF': 5,
    'NeteaseX86': 5, 'OurPlayX86': 5,
    'com.chaozhuo': 5, 'com.vmos': 5, 'com.proxima': 5,
    'CameraCharacteristics': 5,
    'getInstallingPackageName': 5, 'getCertificateChain': 5,
    'SIGKILL': 5, 'tamper': 5,
    'cpuinfo': 5, 'TracerPid': 5, 'sensor_detect': 5, 'NT_PRSTATUS': 5,
    'PTRACE_ATTACH': 5, 'PTRACE_GETREGSET': 5,
    'PTRACE_TRACEME': 5, 'PTRACE_DETACH': 5,
    'OnRecvSignature': 5,
    'sub_4A14AC': 5, 'sub_4A1060': 5, 'loc_1C2990': 5,

    # 权重 4 — 高价值
    'prctl': 4, 'Camera2': 4, 'PackageInstaller': 4, 'exit_group': 4,
    'waitpid': 4, '__WALL': 4, 'sendmsg': 4,
    'socket': 4, 'connect': 4, 'sendto': 4,
    'OnRecvData': 4, 'RecordTouch': 4, 'TouchMonitor': 4,
    'is_root': 4, 'is_unlock': 4, 'emulator': 4, 'tracer': 4,
    'debugger': 4, 'hook': 4, 'gcloud': 4, 'GP6_': 4,
    'RegisterNatives': 4, 'checksum': 4, 'integrity': 4,
    'sub_3519B4': 4, 'sub_351A54': 4, 'sub_1C5B20': 4,

    # 权重 3 — 中等
    'sub_32C4DC': 3, 'sub_32CD20': 3,
    '/proc/': 3, '/sys/': 3, '/dev/': 3,
    'sigaction': 3, 'getppid': 3, 'getauxval': 3,
    'pthread_kill': 3, 'tgkill': 3,
    'FindClass': 3, 'GetMethodID': 3,
    'crc': 3, 'signature': 3,
    'kill': 3, 'Assert': 3, 'hasMatchRate': 3,
    '0xCAFE': 3,

    # 权重 2 — 弱信号
    'sub_35B9A4': 2, 'sub_35C954': 2, 'sub_35FF28': 2, 'sub_35CDD0': 2,
    'sub_3604C8': 2, 'sub_35D480': 2, 'sub_360EE8': 2, 'sub_35EC1C': 2,
    'sub_35E320': 2, 'sub_35BBE4': 2, 'sub_35F74C': 2,
    'CallObjectMethod': 2, 'JNIEnv': 2, 'AnoSDK': 2, 'ace_': 2,
    'Hardware': 2, 'Serial': 2, 'Revision': 2,
    'clock_gettime': 2, 'virtual': 2,

    # 权重 1 — 噪音级
    'root': 1, 'toString': 1, 'jni': 1,
}

KEYWORDS_GENERIC: dict[str, int] = {
    # 面向任何 Android/Linux 反作弊 / 反调试 SDK 的通用关键词
    'ptrace': 5, 'seccomp': 5, 'prctl': 4,
    '/proc/self/maps': 5, '/proc/self/status': 5,
    '/proc/kallsyms': 5, '/proc/modules': 5, '/proc/cpuinfo': 5,
    'zygisk': 5, 'magisk': 5, 'frida': 5, 'xposed': 5,
    'inline_hook': 5,
    'PTRACE_ATTACH': 5, 'PTRACE_GETREGSET': 5, 'PTRACE_TRACEME': 5,
    'TracerPid': 5, 'SIGKILL': 5, 'tamper': 5,
    'CameraCharacteristics': 5,
    'getInstallingPackageName': 5, 'getCertificateChain': 5,
    'inotify': 4, 'readlink': 4,
    'waitpid': 4, '__WALL': 4,
    'socket': 4, 'connect': 4, 'sendto': 4, 'sendmsg': 4,
    'sigaction': 4, 'getauxval': 4,
    'RegisterNatives': 4,
    'emulator': 4, 'debugger': 4, 'tracer': 4, 'hook': 4, 'is_root': 4,
    'exit_group': 4, 'checksum': 4, 'integrity': 4,
    'Camera2': 4, 'PackageInstaller': 4,
    'FindClass': 3, 'GetMethodID': 3,
    '/proc/': 3, '/sys/': 3, '/dev/': 3,
    'pthread_kill': 3, 'tgkill': 3, 'getppid': 3,
    'clock_gettime': 2,
    'abort': 3, 'kill': 3, 'crc': 3,
    'BEEF': 5, 'DEADBEEF': 5, '0xCAFE': 3,
    'JNIEnv': 2, 'virtual': 2, 'root': 1, 'toString': 1, 'jni': 1,
}

PRESETS = {
    'ace': KEYWORDS_ACE,
    'generic': KEYWORDS_GENERIC,
}


# ==================== 评分 ====================

KEYWORD_HIT_CAP = 3  # 单个关键词命中次数上限，防止刷分


def score_body(body: str, keywords: dict[str, int]) -> tuple[int, list[str]]:
    """返回 (score, hits)；hits = [kw×cnt, ...]，按贡献分降序排列。"""
    if is_stdlib_noise(body):
        return 0, []
    total = 0
    hit_items: list[tuple[int, str]] = []
    for kw, w in keywords.items():
        cnt = body.count(kw)
        if cnt:
            contribution = w * min(cnt, KEYWORD_HIT_CAP)
            total += contribution
            hit_items.append((contribution, f'{kw}×{cnt}'))
    hit_items.sort(key=lambda x: (-x[0], x[1]))
    return total, [hit for _, hit in hit_items]


# ==================== 地址区段过滤 ====================

def parse_addr(filename: str) -> int | None:
    """文件名如 '1D0634.c' 或 'sub_1D0634.c' → 0x1D0634"""
    base = os.path.splitext(filename)[0]
    base = base.removeprefix('sub_')
    try:
        return int(base, 16)
    except ValueError:
        return None


def normalize_func_name(name: str) -> str:
    """统一函数文件名 / 地址写法：
    'sub_1D0634.c'、'1D0634.c'、'1d0634'、'0x1D0634' → '1D0634'"""
    base = os.path.splitext(name.strip())[0]
    s = base.upper().removeprefix('SUB_')
    # 去掉可选的 0x / 0X 前缀
    if s.startswith('0X'):
        s = s[2:]
    return s


# ==================== 主流程 ====================

def audit(
    decompile_dir: Path,
    keywords: dict[str, int],
    addr_max: int | None = None,
    min_score: int = 1,
) -> list[tuple[int, str, list[str]]]:
    """
    返回按 score 降序排序的 (score, filename, hits) 列表。

    addr_max: 若提供，过滤掉文件名对应地址 >= addr_max 的（stdlib 内嵌）
    """
    results: list[tuple[int, str, list[str]]] = []

    stats = {
        'total': 0,
        'too_small': 0,
        'thunk_or_trivial': 0,
        'high_addr': 0,
        'stdlib_noise': 0,
        'scored': 0,
    }

    for entry in os.scandir(decompile_dir):
        if not entry.is_file() or not entry.name.endswith('.c'):
            continue
        stats['total'] += 1
        path = Path(entry.path)

        # 地址过滤
        if addr_max is not None:
            addr = parse_addr(entry.name)
            if addr is not None and addr >= addr_max:
                stats['high_addr'] += 1
                continue

        # 大小快速过滤
        if path.stat().st_size < MIN_FILE_SIZE:
            stats['too_small'] += 1
            continue

        try:
            body = path.read_text(errors='ignore')
        except OSError:
            continue

        # thunk / trivial
        if is_trivial(path, body):
            stats['thunk_or_trivial'] += 1
            continue

        # 评分（is_stdlib_noise 在 score_body 里处理）
        s, hits = score_body(body, keywords)
        if s == 0 and is_stdlib_noise(body):
            stats['stdlib_noise'] += 1
            continue
        if s >= min_score:
            results.append((s, entry.name, hits))
            stats['scored'] += 1

    results.sort(key=lambda x: (-x[0], x[1]))

    # 打印统计到 stderr
    print(f'[fn_audit] scanned {stats["total"]} files:', file=sys.stderr)
    print(f'  - too small (<{MIN_FILE_SIZE}B):   {stats["too_small"]}', file=sys.stderr)
    print(f'  - thunk / trivial:        {stats["thunk_or_trivial"]}', file=sys.stderr)
    print(f'  - stdlib noise:           {stats["stdlib_noise"]}', file=sys.stderr)
    if addr_max is not None:
        print(f'  - addr >= {addr_max:#x}:     {stats["high_addr"]}', file=sys.stderr)
    print(f'  = scored ({min_score}+):             {stats["scored"]}', file=sys.stderr)

    return results


# ==================== CLI ====================

def main() -> int:
    p = argparse.ArgumentParser(
        description='筛选 IDA decompile 函数库里高价值的审查目标',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument('decompile_dir', type=Path, help='反编译 .c 文件所在目录')
    p.add_argument('--out', type=Path, default=None, help='输出文件（默认 stdout）')
    p.add_argument('--preset', choices=list(PRESETS.keys()) + ['custom'],
                   default='ace', help='关键词预设（默认 ace）')
    p.add_argument('--keywords-file', type=Path, default=None,
                   help='自定义关键词 JSON 文件 (dict[str, int])；与 --preset custom 配合')
    p.add_argument('--addr-max', type=lambda x: int(x, 0), default=None,
                   help='过滤文件名地址 >= 此值（例如 0x4FC000 排除 libstdc++）')
    p.add_argument('--min-score', type=int, default=1, help='最低分数（默认 1）')
    p.add_argument('--top', type=int, default=None,
                   help='只输出 Top N（默认全部输出）')
    p.add_argument('--exclude-file', type=Path, default=None,
                   help='已分析函数名列表（每行一个十六进制地址或文件名），排除掉')
    args = p.parse_args()

    # 选关键词
    if args.preset == 'custom':
        if not args.keywords_file:
            p.error('--preset custom 需要 --keywords-file')
        raw = json.loads(args.keywords_file.read_text())
        # 过滤掉注释键（以 "//" 开头）和非数字权重
        keywords = {
            k: int(v) for k, v in raw.items()
            if not k.startswith('//') and isinstance(v, (int, float))
        }
        if not keywords:
            p.error('--keywords-file 没有有效的 "keyword": <weight> 条目')
    else:
        keywords = PRESETS[args.preset]

    # 排除列表
    exclude: set[str] = set()
    if args.exclude_file:
        for line in args.exclude_file.read_text().splitlines():
            s = normalize_func_name(line)
            if s:
                exclude.add(s)

    # 扫描
    results = audit(
        args.decompile_dir,
        keywords,
        addr_max=args.addr_max,
        min_score=args.min_score,
    )

    # 过滤 exclude
    if exclude:
        before = len(results)
        results = [
            r for r in results
            if normalize_func_name(r[1]) not in exclude
        ]
        print(f'  - excluded (already analyzed): {before - len(results)}',
              file=sys.stderr)

    # 截断
    if args.top:
        results = results[:args.top]

    # 输出
    lines = []
    for rank, (s, fn, hits) in enumerate(results, 1):
        hit_str = ','.join(hits[:5])
        lines.append(f'{rank:4}. {s:>4}  {fn:<16}  {hit_str}')

    out = '\n'.join(lines) + '\n'
    if args.out:
        args.out.write_text(out)
        print(f'\n[fn_audit] wrote {len(results)} rows → {args.out}',
              file=sys.stderr)
    else:
        print(out)

    return 0


if __name__ == '__main__':
    sys.exit(main())
