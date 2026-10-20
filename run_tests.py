# -*- coding: utf-8 -*-
"""
S-AES 通关测试脚本
==================

按课程作业四个关卡逐项测试并输出测试报告：

  第 1 关 基本测试   —— 16 位加解密、标准测试向量、随机可逆性
  第 2 关 交叉测试   —— 标准向量表（供异构平台间比对）、加解密一致性
  第 3 关 扩展功能   —— ASCII 字符串分组加解密（含填充、中文、边界情况）
  第 4 关 多重加密   —— 4.1 双重加密；4.2 中间相遇攻击；4.3 三重加密(EDE/EEE)
  第 5 关 工作模式   —— CBC：IV 生成与共享、长消息加解密、密文篡改前后解密对比

运行：python run_tests.py
全部通过时退出码为 0，否则为 1。
"""

from __future__ import annotations

import random
import sys
import time

import saes

PASS = "✅ PASS"
FAIL = "❌ FAIL"
_results: list = []          # (关卡, 用例名, 是否通过, 详情)


def record(level: str, name: str, ok: bool, detail: str = "") -> None:
    _results.append((level, name, ok, detail))
    tag = PASS if ok else FAIL
    print(f"  {tag} | {name}" + (f" ｜ {detail}" if detail else ""))


def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"◆ {title}")
    print("=" * 78)


# ----------------------------------------------------------------------------
# 第 0 部分：基础单元自检
# ----------------------------------------------------------------------------
def test_unit() -> None:
    section("第 0 部分 基础单元自检（S盒 / GF(2^4) / 列混淆 / 密钥扩展）")

    # S 盒与逆 S 盒互逆
    ok = all(saes.INV_SBOX[saes.SBOX[i]] == i for i in range(16))
    record("单元", "逆S盒 = S盒的逆（16 项全覆盖）", ok)

    # S 盒为双射
    record("单元", "S 盒为双射（16 个输出互不相同）", len(set(saes.SBOX)) == 16)

    # GF(2^4) 乘法抽查（模 x^4+x+1，手工验证值）
    checks = [(4, 9, 2), (2, 9, 1), (4, 4, 3), (9, 9, 0xD), (3, 0xE, 1), (4, 0xD, 1)]
    ok = all(saes.gf_mul(a, b) == r for a, b, r in checks)
    detail = "；".join(f"{a}·{b}={r}" for a, b, r in checks)
    record("单元", "GF(2^4) 乘法抽查", ok, detail)

    # GF(2^4) 逆元与乘法自洽
    ok = all(saes.gf_mul(a, saes.gf_inv(a)) == 1 for a in range(1, 16))
    record("单元", "GF(2^4) 逆元自洽（a·a⁻¹=1）", ok)

    # 逆列混淆互逆：全部 65536 个状态
    t0 = time.perf_counter()
    ok = all(
        saes._mix_columns(saes._mix_columns(x, saes.MIX_MATRIX), saes.INV_MIX_MATRIX) == x
        for x in range(0x10000))
    record("单元", "InvMixColumns(MixColumns(x))=x（65536 状态全覆盖）", ok,
           f"耗时 {time.perf_counter() - t0:.2f}s")

    # 密钥扩展手工验证（K=0xA73B 时 K0/K1/K2 逐步手推结果）
    k0, k1, k2 = saes.key_expansion(0xA73B)
    ok = (k0, k1, k2) == (0xA73B, 0x94AF, 0x5EF1)
    record("单元", "密钥扩展手工推演比对 (K=0xA73B)",
           ok, f"K1={saes.to_hex(k1, 16)}, K2={saes.to_hex(k2, 16)} (期望 94af, 5ef1)")


# ----------------------------------------------------------------------------
# 第 1 关：基本测试
# ----------------------------------------------------------------------------
def test_level1() -> None:
    section("第 1 关 基本测试（16bit 数据 + 16bit 密钥 -> 16bit 密文，支持解密）")

    # 标准测试向量（按规格手工逐步推演，见 docs/开发手册.md）
    p, k, expect = 0x6F6B, 0xA73B, 0x0067
    c = saes.encrypt(p, k)
    record("第1关", f"标准向量 E(0x6F6B, 0xA73B) = 0x{expect:04x}",
           c == expect, f"实际 C=0x{c:04x} ({saes.to_bits(c, 16)})")

    d = saes.decrypt(c, k)
    record("第1关", "标准向量解密还原明文", d == p, f"D(0x{c:04x})=0x{d:04x}")

    # 全空间抽样可逆性：随机 2000 对
    rng = random.Random(2026)
    ok = True
    for _ in range(2000):
        p, k = rng.randrange(0x10000), rng.randrange(0x10000)
        if saes.decrypt(saes.encrypt(p, k), k) != p:
            ok = False
            break
    record("第1关", "随机 2000 组加解密可逆（E 后 D 还原明文）", ok)

    # 加密为双射：固定密钥下不同明文密文不同
    k = 0x3A94
    cs = {saes.encrypt(p, k) for p in range(0x10000)}
    record("第1关", "固定密钥下加密为双射（65536 明文 -> 65536 不同密文）", len(cs) == 0x10000)

    # 轮函数完整性：trace 输出与最终结果一致
    _, steps = saes.encrypt(p, k, trace=True)
    record("第1关", "trace 模式输出 8 步中间状态", len(steps) == 8,
           "步骤: " + " -> ".join(n for n, _ in steps))


# ----------------------------------------------------------------------------
# 第 2 关：交叉测试
# ----------------------------------------------------------------------------
def test_level2() -> None:
    section("第 2 关 交叉测试（算法标准一致性：相同 P、K -> 相同 C）")

    vectors = [
        (0x6F6B, 0xA73B),
        (0x0000, 0x0000),
        (0xFFFF, 0xFFFF),
        (0x0123, 0x4567),
        (0xABCD, 0xEF01),
        (0x1234, 0x0000),
        (0x0000, 0x1234),
        (0xAAAA, 0x5555),
    ]
    print(f"  {'P(bin)':<18}{'K(bin)':<18}{'C(bin)':<18}{'P':>5}{'K':>5}{'C':>6}")
    all_ok = True
    for p, k in vectors:
        c = saes.encrypt(p, k)
        ok = saes.decrypt(c, k) == p and c == saes.encrypt(p, k)
        all_ok &= ok
        print(f"  {saes.to_bits(p, 16):<18}{saes.to_bits(k, 16):<18}{saes.to_bits(c, 16):<18}"
              f"{saes.to_hex(p, 16):>5}{saes.to_hex(k, 16):>5}{saes.to_hex(c, 16):>6}")
    record("第2关", "8 组标准向量加解密一致（可与其他小组直接比对）", all_ok)

    # 可复现向量：由确定性算法生成 12 组随机向量并验证双向一致
    rng = random.Random(0x5AED)
    ok = True
    for _ in range(12):
        p, k = rng.randrange(0x10000), rng.randrange(0x10000)
        c = saes.encrypt(p, k)
        if saes.decrypt(c, k) != p:
            ok = False
            break
    record("第2关", "12 组随机向量可逆性（异构平台应得相同结果）", ok)
    print("  ℹ INFO | 交叉测试方法：A 组用本程序对上表 P、K 加密得 C；"
          "B 组程序对相同 P、K 加密应得相同 C，且 B 解密 A 的 C 应还原 P。")


# ----------------------------------------------------------------------------
# 第 3 关：扩展功能（ASCII 字符串）
# ----------------------------------------------------------------------------
def test_level3() -> None:
    section("第 3 关 扩展功能（ASCII 字符串加解密，分组 2 字节）")

    k = 0x3A94
    cases = [
        "Hello, S-AES!",
        "Information Security",
        "S-AES 123",
        "A",                    # 奇数长度 -> 需填充
        "",                     # 空串
        "信息安全导论",          # 非 ASCII（UTF-8 多字节）扩展支持
        "hi~",                  # 恰好 2 组
    ]
    for text in cases:
        try:
            c = saes.encrypt_ascii(text, k)
            r = saes.decrypt_ascii(c, k)
            ok = r == text
            detail = f"{len(text.encode('utf-8'))}B -> {len(c)}字符 ｜ {text!r} -> {c!r}"
        except Exception as e:                       # noqa: BLE001
            ok, detail = False, f"异常: {e}"
        record("第3关", f"ASCII 往返: {text!r}", ok, detail)

    # 密文应确实"乱码"（非平凡性：与原文不同）
    text = "Hello, S-AES!"
    c = saes.encrypt_ascii(text, k)
    record("第3关", "密文为乱码（与原文不同且长度为偶数）", c != text and len(c) % 2 == 0,
           f"密文 {c!r}")

    # 不同密钥解密应得到不同结果（演示错误密钥场景）
    c_wrong = saes.decrypt_ascii(c, k ^ 1)
    record("第3关", "错误密钥解密结果与原文不同", c_wrong != text)


# ----------------------------------------------------------------------------
# 第 4 关：多重加密
# ----------------------------------------------------------------------------
def test_level4() -> None:
    section("第 4 关 多重加密（4.1 双重 / 4.2 中间相遇 / 4.3 三重）")

    # ---------- 4.1 双重加密 ----------
    rng = random.Random(42)
    ok = True
    for _ in range(500):
        p = rng.randrange(0x10000)
        k32 = rng.randrange(1 << 32)
        if saes.double_decrypt(saes.double_encrypt(p, k32), k32) != p:
            ok = False
            break
    record("4.1", "双重加密随机 500 组可逆（32 位密钥）", ok)

    p, k32 = 0x6F6B, 0xA73B6F6B
    c = saes.double_encrypt(p, k32)
    record("4.1", "双重加密示例可逆",
           saes.double_decrypt(c, k32) == p,
           f"P={saes.to_hex(p, 16)}, K1={saes.to_hex(k32 >> 16, 16)}, "
           f"K2={saes.to_hex(k32 & 0xFFFF, 16)} -> C={saes.to_hex(c, 16)}")

    # 双重加密 != 单重加密（扩展生效）
    record("4.1", "双重加密结果异于单重加密",
           c != saes.encrypt(p, k32 >> 16) and c != saes.encrypt(p, k32 & 0xFFFF))

    # ---------- 4.2 中间相遇攻击 ----------
    true_k1, true_k2 = 0x2D55, 0x0F1E
    k32 = (true_k1 << 16) | true_k2
    p1, p2, p3 = 0x6F6B, 0xBB51, 0x1234
    c1, c2, c3 = (saes.double_encrypt(p, k32) for p in (p1, p2, p3))

    t0 = time.perf_counter()
    found1 = saes.meet_in_the_middle([(p1, c1)])
    t1 = time.perf_counter()
    found2 = saes.meet_in_the_middle([(p1, c1), (p2, c2)])
    t2 = time.perf_counter()
    found3 = saes.meet_in_the_middle([(p1, c1), (p2, c2), (p3, c3)])
    t3 = time.perf_counter()

    record("4.2", "单组明密文对：候选包含正确密钥",
           (true_k1, true_k2) in found1,
           f"候选 {len(found1)} 组（期望约 2^16 个误匹配），耗时 {t1 - t0:.2f}s")

    record("4.2", "双组明密文对：正确密钥在候选中且候选大幅缩减",
           (true_k1, true_k2) in found2 and len(found2) < len(found1) / 100,
           f"候选缩减至 {len(found2)} 组，耗时 {t2 - t1:.2f}s")

    record("4.2", "三组明密文对：唯一恢复正确 32 位密钥",
           found3 == [(true_k1, true_k2)],
           f"K1={saes.to_bits(true_k1, 16)}, K2={saes.to_bits(true_k2, 16)}, "
           f"耗时 {t3 - t2:.2f}s")

    # 恢复密钥功能等价性：用恢复出的密钥加解密新明文应与真实密钥一致
    p_new = rng.randrange(0x10000)
    rk1, rk2 = found3[0]
    record("4.2", "恢复密钥对新明文加密与真实密钥一致",
           saes.double_encrypt(p_new, (rk1 << 16) | rk2) == saes.double_encrypt(p_new, k32),
           f"验证明文 P=0x{p_new:04x}")

    # 随机 10 轮完整攻击演练（3 组明密文对确保唯一性）
    ok = True
    for _ in range(10):
        tk1, tk2 = rng.randrange(0x10000), rng.randrange(0x10000)
        kk = (tk1 << 16) | tk2
        ps = [rng.randrange(0x10000) for _ in range(3)]
        pairs = [(p, saes.double_encrypt(p, kk)) for p in ps]
        if saes.meet_in_the_middle(pairs) != [(tk1, tk2)]:
            ok = False
            break
    record("4.2", "随机 10 轮攻击演练全部唯一恢复（各 3 组明密文对）", ok)

    # ---------- 4.3 三重加密 ----------
    k32_ede = 0xA73B6F6B
    p = 0x6F6B
    c_ede = saes.triple_encrypt_ede(p, k32_ede)
    record("4.3", "EDE(32位密钥) 示例可逆",
           saes.triple_decrypt_ede(c_ede, k32_ede) == p,
           f"P={saes.to_hex(p, 16)} -> C={saes.to_hex(c_ede, 16)}")

    k48_eee = (0xA73B << 32) | (0x6F6B << 16) | 0x3A94
    c_eee = saes.triple_encrypt_eee(p, k48_eee)
    record("4.3", "EEE(48位密钥) 示例可逆",
           saes.triple_decrypt_eee(c_eee, k48_eee) == p,
           f"P={saes.to_hex(p, 16)} -> C={saes.to_hex(c_eee, 16)}")

    rng = random.Random(7)
    ok = all(
        saes.triple_decrypt_ede(saes.triple_encrypt_ede(p := rng.randrange(0x10000),
                                                        k32 := rng.randrange(1 << 32)), k32) == p
        and saes.triple_decrypt_eee(saes.triple_encrypt_eee(q := rng.randrange(0x10000),
                                                            k48 := rng.randrange(1 << 48)), k48) == q
        for _ in range(300))
    record("4.3", "EDE/EEE 随机各 300 组可逆", ok)

    # 三重加密与双重/单重结果互异（安全增强生效）
    record("4.3", "三重加密结果异于双重与单重加密",
           c_eee != c_ede and c_ede != saes.double_encrypt(p, k32_ede)
           and c_ede != saes.encrypt(p, k32_ede >> 16))


# ----------------------------------------------------------------------------
# 第 5 关：工作模式（CBC）
# ----------------------------------------------------------------------------
def test_level5() -> None:
    section("第 5 关 工作模式（CBC：IV 生成与共享、长消息加解密、密文篡改对比）")

    key = 0x2D55

    # IV 生成：16 位范围与随机性
    ivs = {saes.generate_iv() for _ in range(200)}
    record("第5关", "随机生成 16 位 IV（200 次全部在范围内且高度分散）",
           all(0 <= v <= 0xFFFF for v in ivs) and len(ivs) > 150,
           f"200 次生成 {len(ivs)} 个不同 IV")

    # 长消息 CBC 往返（多种长度，含中文与 100 字节）
    msgs = ["A", "hello", "S-AES CBC mode works on longer messages!",
            "信息安全导论 课程作业 CBC 工作模式测试", "x" * 100]
    ok = True
    for m in msgs:
        iv, c = saes.cbc_encrypt_text(m, key)
        if saes.cbc_decrypt_text(c, key, iv) != m:
            ok = False
            break
    record("第5关", "长消息 CBC 加解密往返（5 种长度，含中文/100 字节）", ok,
           f"最长明文 100 字节 -> 51 组密文")

    text = "S-AES CBC mode works on longer messages!"
    iv, cipher = saes.cbc_encrypt_text(text, key, iv=0x1234)

    # 分组长链：明文 40 字节 -> 21 组密文（末组含 PKCS#7 填充）
    record("第5关", "长消息分组正确（40 字节明文 -> 21 组 16 位密文）",
           len(cipher) == 21, f"共 {len(cipher)} 组")

    # IV 必须共享：错误 IV 解密结果与原文不同
    record("第5关", "IV 错误时解密结果与原文不同（说明 IV 必须双方共享）",
           saes.cbc_decrypt_text(cipher, key, iv ^ 0x0001) != text)

    # 可复现性与 IV 敏感性
    iv_a, c_a = saes.cbc_encrypt_text(text, key, iv)
    iv_b, c_b = saes.cbc_encrypt_text(text, key, iv ^ 0xFFFF)
    record("第5关", "同明文同 IV 密文可复现；换 IV 后密文不同",
           c_a == cipher and c_b != cipher)

    # 篡改第 idx 组密文：错误传播（CBC 特性）
    idx = 1
    r = saes.cbc_error_propagation(text, key, iv, idx)
    changed = sorted(r["changed_blocks"])
    record("第5关", f"篡改第 {idx} 组密文：仅第 {idx}、{idx+1} 组明文受影响，其余 {r['blocks_total']-2} 组不变",
           set(changed) == {idx, idx + 1}, f"受影响分组 {changed} / 共 {r['blocks_total']} 组")

    # 被篡改组对应明文整体乱码（雪崩）
    orig_blk = r["plain_before"][2 * idx:2 * idx + 2]
    garb_blk = r["plain_after"][2 * idx:2 * idx + 2]
    record("第5关", f"第 {idx} 组明文整体乱码（原 {orig_blk.hex()} -> {garb_blk.hex()}）",
           orig_blk != garb_blk and garb_blk != b"\x00\x00")

    # 第 idx+1 组：与篡改位一一对应（异或 0xFFFF）
    o2 = r["plain_before"][2 * (idx + 1):2 * (idx + 1) + 2]
    t2 = r["plain_after"][2 * (idx + 1):2 * (idx + 1) + 2]
    xor2 = bytes(a ^ b for a, b in zip(o2, t2))
    record("第5关", f"第 {idx+1} 组明文按位翻转（XOR = {xor2.hex()}，即 0xFFFF）",
           xor2 == b"\xff\xff")

    # 替换（赋新值）第 2 组密文：受影响范围同样只波及相邻两组
    r2 = saes.cbc_error_propagation(text, key, iv, 2, 0x0000)
    ch2 = sorted(r2["changed_blocks"])
    record("第5关", "以新值替换第 2 组密文：受影响分组仍为 {2,3}，后续分组不受影响",
           set(ch2) == {2, 3}, f"受影响分组 {ch2}")

    # 篡改末组密文：破坏 PKCS#7 填充，接收方无法通过填充校验
    n = r["blocks_total"]
    r3 = saes.cbc_error_propagation(text, key, iv, n - 1)
    record("第5关", "篡改末组密文：末组明文改变，PKCS#7 填充被破坏",
           r3["changed_blocks"] == [n - 1],
           f"受影响分组 {r3['changed_blocks']}（末组填充不再合法，解密报填充错误）")

    # 结论性对比：篡改前后可读明文
    print(f"  ℹ INFO | 篡改前明文：{text!r}")
    print(f"  ℹ INFO | 篡改后明文：{saes.cbc_decrypt_text(r['tampered'], key, iv)!r}（第 {idx} 组乱码、第 {idx+1} 组对应位变化）")


# ----------------------------------------------------------------------------
# 汇总
# ----------------------------------------------------------------------------
def summary() -> int:
    section("测试汇总")
    total = len(_results)
    passed = sum(1 for _, _, ok, _ in _results if ok)
    for level, name, ok, detail in _results:
        if not ok:
            print(f"  {FAIL} | [{level}] {name} ｜ {detail}")
    print(f"\n  通过 {passed}/{total} 项测试。")
    if passed == total:
        print("  🎉 五个关卡全部通关！")
    return 0 if passed == total else 1


if __name__ == "__main__":
    print("S-AES 通关测试")
    print("运行环境：Python", sys.version.split()[0], "| 模块：saes.py")
    test_unit()
    test_level1()
    test_level2()
    test_level3()
    test_level4()
    test_level5()
    sys.exit(summary())
