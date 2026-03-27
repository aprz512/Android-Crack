"""
OLLVM CFF 去混淆脚本 — IDA Pro x86/x64
针对 demo_cff 的最简实现

CFF 结构 (demo_cff):
    prologue:   mov [rbp-0x20], INIT_STATE
    dispatcher: mov eax,[rbp-0x20]; mov [rbp-0x24],eax   ← 搬运
                mov eax,[rbp-0x24]; sub eax,STATE; je block  ← 每个 case 独立 load
    real_block: movl $NEXT, [rbp-0x20]; jmp loopEnd       ← 无条件
                cmovCC; mov [rbp-0x20],eax; jmp loopEnd   ← cmov 条件
    loopEnd:    jmp dispatcher
"""

import struct

try:
    import idaapi, idc, ida_bytes, ida_funcs, ida_ua
    IN_IDA = True
except ImportError:
    IN_IDA = False


# ── 工具 ─────────────────────────────────────────────────────────────────────

def mnem(ea):    return idc.print_insn_mnem(ea).lower()
def otype(ea,n): return idc.get_operand_type(ea, n)
def oval(ea,n):  return idc.get_operand_value(ea, n)
def sz(ea):      return idc.get_item_size(ea)
def nxt(ea):     return idc.next_head(ea)
def prv(ea):     return idc.prev_head(ea)
def u32(v):      return v & 0xFFFFFFFF

def is_jmp(ea):  return mnem(ea) == 'jmp'
def is_jcc(ea):  m = mnem(ea); return m.startswith('j') and m not in ('jmp','jrcxz')
def is_cmov(ea): return mnem(ea).startswith('cmov')

def disp_of(ea, n):
    if otype(ea, n) != idc.o_displ: return None
    insn = ida_ua.insn_t(); ida_ua.decode_insn(insn, ea)
    v = insn.ops[n].addr & 0xFFFFFFFF
    return struct.unpack('<i', struct.pack('<I', v))[0]  # sign-extend 32→Python int

def is_store(ea, slot=None):
    """mov [base+disp], src → (disp, imm|None)"""
    if mnem(ea) != 'mov' or otype(ea,0) != idc.o_displ: return None
    d = disp_of(ea, 0)
    if d is None or (slot is not None and d != slot): return None
    t = otype(ea, 1)
    if t == idc.o_imm: return (d, u32(oval(ea,1)))
    if t == idc.o_reg: return (d, None)
    return None

def is_load(ea, slot=None):
    """mov reg, [base+disp] → disp"""
    if mnem(ea) != 'mov' or otype(ea,0) != idc.o_reg or otype(ea,1) != idc.o_displ: return None
    d = disp_of(ea, 1)
    if d is None or (slot is not None and d != slot): return None
    return d


# ── 指令编码 ──────────────────────────────────────────────────────────────────

JCC = {
    'o':0x80,'no':0x81,'b':0x82,'ae':0x83,'nb':0x83,
    'e':0x84,'z':0x84,'ne':0x85,'nz':0x85,
    'be':0x86,'na':0x86,'a':0x87,'nbe':0x87,
    's':0x88,'ns':0x89,'p':0x8a,'pe':0x8a,'np':0x8b,'po':0x8b,
    'l':0x8c,'nge':0x8c,'ge':0x8d,'nl':0x8d,
    'le':0x8e,'ng':0x8e,'g':0x8f,'nle':0x8f,
}

def jmp5(src, dst):
    return b'\xe9' + struct.pack('<i', dst-(src+5))

def jcc6(src, dst, cond):
    op = JCC.get(cond)
    return (b'\x0f' + struct.pack('B', op) + struct.pack('<i', dst-(src+6))) if op else None

def nop(start, end):
    n = end - start
    if n > 0: ida_bytes.patch_bytes(start, b'\x90'*n)


# ── CFF 结构识别 ──────────────────────────────────────────────────────────────

def find_cff(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func: return None

    fc = idaapi.FlowChart(func, flags=(idaapi.FC_PREDS|idaapi.FC_NOEXT))
    bmap = {b.start_ea: b for b in fc}

    # loopEnd = 前驱最多 + 后继=1
    loop = max(bmap.values(), key=lambda b: sum(1 for _ in b.preds()))
    if sum(1 for _ in loop.succs()) != 1:
        print("[!] 找不到 loopEnd"); return None
    print(f"[+] loopEnd    0x{loop.start_ea:x} (前驱 {sum(1 for _ in loop.preds())})")

    # dispatcher 头 = loopEnd 的唯一后继
    disp_ea = list(loop.succs())[0].start_ea
    print(f"[+] dispatcher 0x{disp_ea:x}")

    # 每个 case 在 IDA 里是两个 block:
    #   Block A: mov eax,[disp_var]; sub eax,STATE; je real_block  (2个后继)
    #   Block B: jmp $+5                                            (1个后继→下个A或loopEnd)
    disp_blocks = set()
    real = []
    cur_ea = disp_ea
    while cur_ea is not None and cur_ea not in disp_blocks:
        blk = bmap.get(cur_ea)
        if blk is None: break
        disp_blocks.add(cur_ea)
        succs = list(blk.succs())
        if len(succs) == 2:                          # Block A: je + fall-through
            ft = next(s for s in succs if s.start_ea == blk.end_ea)   # Block B
            jt = next(s for s in succs if s != ft)                     # 真实块
            real.append(jt.start_ea)
            disp_blocks.add(ft.start_ea)
            nxt_ea = next((s.start_ea for s in ft.succs()), None)
            cur_ea = nxt_ea if nxt_ea and nxt_ea != loop.start_ea else None
        else:                                        # 链末尾（单条 jmp loopEnd）
            cur_ea = None

    print(f"[+] 真实块 {len(real)} 个")

    sv = -0x20
    init = 0xd044b3cf
    print(f"[+] store_var=[rbp{sv:+#x}]")
    print(f"[+] init_state 0x{init:x}")

    return dict(func=func, disp_ea=disp_ea, disp_blocks=disp_blocks,
                loop=loop, real=real, bmap=bmap, sv=sv, init=init)


# ── 真实块分析 ────────────────────────────────────────────────────────────────

def analyze(bea, cff):
    # analyze() 只分析“真实块”的出口语义：
    # 这个块执行完以后，会把哪个 state 写回 [rbp-0x20]，
    # 然后 dispatcher 会根据这个 state 决定下一次进入哪个真实块。
    #
    # 它不负责：
    # 1. 找 dispatcher / loopEnd
    # 2. 找哪些块是真实块
    # 3. 建 state -> block 地址映射
    #
    # 它只负责回答：
    # “这个真实块的下一跳 state 是什么？”
    blk = cff['bmap'].get(bea)
    if not blk: return None
    sv, loop_ea, disp_ea = cff['sv'], cff['loop'].start_ea, cff['disp_ea']

    # demo_cff 的真实块出口一定是：
    #   ...
    #   mov [store_var], XXX
    #   jmp loopEnd
    #
    # 所以先取 basic block 最后一条指令，确认它真的是 jmp，
    # 并且目标是 loopEnd（或 IDA 识别成 dispatcher 头）。
    # 如果不是这个形状，就说明这不是我们想要的标准真实块。
    tail = prv(blk.end_ea)
    if not is_jmp(tail) or oval(tail,0) not in (loop_ea, disp_ea): return None

    # 再看跳转前一条。
    # 对 demo_cff 来说，这里应该是：
    #   mov [rbp-0x20], IMM
    # 或
    #   mov [rbp-0x20], reg
    #
    # 也就是把“下一状态”写回 state 变量。
    st_ea = prv(tail)
    r = is_store(st_ea, slot=sv)
    if r is None: return None
    _, imm = r

    if imm is not None:
        # 情况1：直接写立即数。
        #
        # 例如：
        #   mov [rbp-0x20], 0x3556f2b6
        #   jmp loopEnd
        #
        # 这表示这个真实块“无条件”跳到下一个 state。
        # 后面 patch_all() 会把它改成一个真正的 jmp 真实块地址。
        return {'kind':'uncond', 'state':imm, 'ps':st_ea, 'pe':tail+sz(tail)}

    # 情况2：不是写立即数，而是写一个寄存器。
    #
    # demo_cff 的条件块长这样：
    #   mov  false_state, eax
    #   mov  true_state,  ecx
    #   cmp  ...
    #   cmovXX ecx, eax
    #   mov  [rbp-0x20], eax
    #   jmp  loopEnd
    #
    # 所以这里继续往前找 cmov。
    scan = prv(st_ea)
    for _ in range(8):
        if scan < blk.start_ea: break
        if is_cmov(scan):
            # 找到 cmov 之后，先读它的两个寄存器。
            #
            # 例如：cmovl ecx, eax
            #   dst = eax  ← 条件不成立时保留的默认值（false_state）
            #   src = ecx  ← 条件成立时覆盖进去的值（true_state）
            insn = ida_ua.insn_t(); ida_ua.decode_insn(insn, scan)
            dst, src = insn.ops[0].reg, insn.ops[1].reg

            # 再继续往前找：mov reg, IMM
            # 这里只关心 cmov 用到的两个寄存器 src/dst，
            # 其它无关 mov 立即数一律忽略，避免把业务常量误当成 state。
            rv, need, s = {}, {src, dst}, prv(scan)
            for _ in range(8):
                if s < blk.start_ea: break
                if mnem(s) == 'mov' and otype(s,0) == idc.o_reg and otype(s,1) == idc.o_imm:
                    i2 = ida_ua.insn_t(); ida_ua.decode_insn(i2, s)
                    r = i2.ops[0].reg
                    if r in need and r not in rv:
                        rv[r] = u32(oval(s,1))
                        if len(rv) == 2: break
                s = prv(s)

            # cmov 语义：
            #   条件不成立 → dst 保持原值
            #   条件成立   → src 赋给 dst
            #
            # 所以：
            #   true_state  = src 原来的立即数
            #   false_state = dst 原来的立即数
            st_v, sf_v = rv.get(src), rv.get(dst)
            if st_v is not None and sf_v is not None:
                # 返回 patch 所需的最小信息：
                #   cond : 条件码（如 l / e / ge）
                #   st   : true 分支 state
                #   sf   : false 分支 state
                #   ps~pe: 后面要覆盖掉的机器码范围
                return {'kind':'cond', 'cond':mnem(scan)[4:],
                        'st':st_v, 'sf':sf_v, 'ps':scan, 'pe':tail+sz(tail)}
            break
        scan = prv(scan)

    # 能走到这里，说明这个真实块不是我们预期的两种出口：
    # 1. mov [sv], IMM ; jmp loopEnd
    # 2. cmov... ; mov [sv], reg ; jmp loopEnd
    #
    # 对 demo_cff 来说，这种块直接忽略即可。
    return None


# ── state → block 映射 ───────────────────────────────────────────────────────

def build_map(cff):
    """sub/cmp 立即数直接就是 state_val（每个 case 独立 load）"""
    real_set, m = set(cff['real']), {}
    for bea in cff['disp_blocks']:
        blk = cff['bmap'].get(bea)
        if not blk: continue
        ea = bea
        while ea < blk.end_ea:
            if mnem(ea) in ('sub', 'cmp') and otype(ea,1) == idc.o_imm:
                nx = nxt(ea)
                if is_jcc(nx) and oval(nx,0) in real_set:
                    m[u32(oval(ea,1))] = oval(nx,0)
            ea = nxt(ea)
    return m


# ── Patch ────────────────────────────────────────────────────────────────────

def patch_all(cff, transitions, smap):
    patched = 0
    for t in transitions:
        ps, pe = t['ps'], t['pe']

        if t['kind'] == 'uncond':
            tgt = smap.get(t['state'])
            if tgt is None: print(f"  [!] state 0x{t['state']:x} 未映射"); continue
            ida_bytes.patch_bytes(ps, jmp5(ps, tgt) + b'\x90'*(pe-ps-5))
            print(f"  [OK] 0x{ps:x}: jmp 0x{tgt:x}"); patched += 1

        elif t['kind'] == 'cond':
            tgt_t, tgt_f = smap.get(t['st']), smap.get(t['sf'])
            if tgt_t is None or tgt_f is None: print(f"  [!] cond state 未映射"); continue
            jb = jcc6(ps, tgt_t, t['cond'])
            if jb is None: print(f"  [!] 未知条件码 {t['cond']}"); continue
            ida_bytes.patch_bytes(ps, jb + jmp5(ps+6, tgt_f) + b'\x90'*(pe-ps-11))
            print(f"  [OK] 0x{ps:x}: j{t['cond']} 0x{tgt_t:x}/jmp 0x{tgt_f:x}"); patched += 1

    # prologue jmp → 第一个真实块
    first = smap.get(cff['init'])
    if first:
        ea = cff['func'].start_ea
        while ea < cff['disp_ea']:
            if is_jmp(ea) and oval(ea,0) == cff['disp_ea']:
                ida_bytes.patch_bytes(ea, jmp5(ea, first))
                print(f"  [OK] prologue → 0x{first:x}"); break
            ea = nxt(ea)

    # NOP 所有 dispatcher 块 + loopEnd
    for bea in cff['disp_blocks']:
        blk = cff['bmap'].get(bea)
        if blk: nop(blk.start_ea, blk.end_ea)
    nop(cff['loop'].start_ea, cff['loop'].end_ea)
    print(f"  [OK] NOP dispatcher + loopEnd")
    return patched


# ── 主函数 ───────────────────────────────────────────────────────────────────

def deflat(func_ea):
    print(f"\n[*] 去混淆 @ 0x{func_ea:x}")
    cff = find_cff(func_ea)
    if not cff: return

    print("\n[*] 分析真实块...")
    transitions = []
    for bea in cff['real']:
        t = analyze(bea, cff)
        if t:
            transitions.append(t)
            if t['kind'] == 'uncond': print(f"    0x{bea:x}: → 0x{t['state']:x}")
            else: print(f"    0x{bea:x}: j{t['cond']} 0x{t['st']:x}/0x{t['sf']:x}")
        else:
            print(f"    0x{bea:x}: [跳过]")

    smap = build_map(cff)
    print(f"\n[+] 映射 {len(smap)}/{len(cff['real'])} 个状态")

    print("\n[*] Patch...")
    n = patch_all(cff, transitions, smap)
    print(f"\n[*] 完成，patch {n} 个块")
    idc.refresh_idaview_anyway()


def main():
    if not IN_IDA: print("请在 IDA Pro 中运行"); return
    ea = idc.here()
    f = ida_funcs.get_func(ea)
    if f: ea = f.start_ea
    s = idaapi.ask_str(f"0x{ea:x}", 0, "函数地址:")
    if not s: return
    try: deflat(int(s, 16))
    except ValueError: print(f"[!] 无效地址: {s}")

if __name__ == '__main__':
    main()
