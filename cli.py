# -*- coding: utf-8 -*-
"""
S-AES 命令行工具（第 2 关交叉测试专用）
=======================================

用于与不同小组/平台进行交叉测试。所有输入输出均为标准格式：
  - 二进制：连续 16/32/48 位 0/1 串（可含空格）
  - 十六进制：4/8/12 位 hex（可加 0x 前缀）

用法示例：
  python cli.py encrypt  -k 1010011100111011 -p 0110111101101011
  python cli.py decrypt  -k 1010011100111011 -c 0000000001100111
  python cli.py encrypt  -k a73b -p 6f6b --fmt hex
  python cli.py encrypt-ascii  -k 3a94 -t "Hello, S-AES!"
  python cli.py decrypt-ascii  -k 3a94 -t "<密文字符串>"
  python cli.py double-encrypt  -k <32bit密钥> -p <16bit明文>
  python cli.py double-decrypt  -k <32bit密钥> -c <16bit密文>
  python cli.py triple-encrypt  -k <48bit密钥> -p <16bit明文> --mode eee
  python cli.py triple-encrypt  -k <32bit密钥> -p <16bit明文> --mode ede
  python cli.py triple-decrypt  -k <密钥> -c <16bit密文> --mode ede
  python cli.py mitm -p <明文1> -c <密文1> [-p2 <明文2> -c2 <密文2> ...]
  python cli.py vectors            # 打印标准测试向量供交叉比对
"""

from __future__ import annotations

import argparse
import sys

import saes


def parse_key16(s: str, fmt: str) -> int:
    return saes.parse_bits(s, 16, "key") if fmt == "bin" else saes.parse_hex(s, 16, "key")


def parse_data16(s: str, fmt: str, name: str) -> int:
    return saes.parse_bits(s, 16, name) if fmt == "bin" else saes.parse_hex(s, 16, name)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cli.py",
        description="S-AES 命令行工具：支持基本加解密、ASCII 串、多重加密与中间相遇攻击",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法示例：")[-1],
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_fmt(sp):
        sp.add_argument("-k", "--key", required=True, help="16 位密钥（二进制或十六进制）")
        sp.add_argument("--fmt", choices=["bin", "hex"], default="bin",
                        help="输入格式：bin（默认）或 hex")

    # 基本加解密
    sp = sub.add_parser("encrypt", help="第1关：16 位明文加密")
    add_fmt(sp)
    sp.add_argument("-p", "--plaintext", required=True, help="16 位明文")
    sp.add_argument("--trace", action="store_true", help="输出每步中间状态")

    sp = sub.add_parser("decrypt", help="第1关：16 位密文解密")
    add_fmt(sp)
    sp.add_argument("-c", "--ciphertext", required=True, help="16 位密文")
    sp.add_argument("--trace", action="store_true", help="输出每步中间状态")

    # ASCII
    sp = sub.add_parser("encrypt-ascii", help="第3关：ASCII 字符串加密")
    add_fmt(sp)
    sp.add_argument("-t", "--text", required=True, help="明文字符串")

    sp = sub.add_parser("decrypt-ascii", help="第3关：ASCII 密文字符串解密")
    add_fmt(sp)
    sp.add_argument("-t", "--text", required=True, help="密文字符串（可为乱码）")

    # 双重加密
    sp = sub.add_parser("double-encrypt", help="第4.1关：双重加密（32 位密钥 K1||K2）")
    add_fmt(sp)
    sp.add_argument("-p", "--plaintext", required=True, help="16 位明文")

    sp = sub.add_parser("double-decrypt", help="第4.1关：双重解密")
    add_fmt(sp)
    sp.add_argument("-c", "--ciphertext", required=True, help="16 位密文")

    # 三重加密
    for name, fn, arg in (("triple-encrypt", True, "-p"),
                          ("triple-decrypt", False, "-c")):
        sp = sub.add_parser(name, help="第4.3关：三重加密/解密（--mode ede 用 32 位密钥，eee 用 48 位密钥）")
        add_fmt(sp)
        sp.add_argument(arg, dest="data", required=True,
                        help="16 位明文" if fn else "16 位密文")
        sp.add_argument("--mode", choices=["ede", "eee"], default="ede",
                        help="ede=32位密钥EDE模式（默认），eee=48位密钥EEE模式")

    # 中间相遇攻击
    sp = sub.add_parser("mitm", help="第4.2关：中间相遇攻击恢复双重加密密钥 (K1,K2)")
    sp.add_argument("-p", "--ptext", required=True, help="已知明文（二进制 16 位）")
    sp.add_argument("-c", "--ctext", required=True, help="已知密文（二进制 16 位）")
    sp.add_argument("-p2", "--ptext2", help="第二组明文（可选，用于过滤误匹配）")
    sp.add_argument("-c2", "--ctext2", help="第二组密文（可选）")

    # 标准测试向量
    sub.add_parser("vectors", help="打印标准测试向量（供与其他小组交叉比对）")
    return p


def fmt_key(args) -> int:
    return parse_key16(args.key, args.fmt)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    fmt = getattr(args, "fmt", "bin")

    if args.cmd == "encrypt":
        key = fmt_key(args)
        p = parse_data16(args.plaintext, fmt, "plaintext")
        c = saes.encrypt(p, key)
        print(f"密钥   : {saes.to_bits(key, 16)} ({saes.to_hex(key, 16)})")
        print(f"明文 P : {saes.to_bits(p, 16)} ({saes.to_hex(p, 16)})")
        print(f"密文 C : {saes.to_bits(c, 16)} ({saes.to_hex(c, 16)})")
        if args.trace:
            _, steps = saes.encrypt(p, key, trace=True)
            for name, st in steps:
                print(f"  [{name:>18}] {saes.to_bits(st, 16)}")
        return 0

    if args.cmd == "decrypt":
        key = fmt_key(args)
        c = parse_data16(args.ciphertext, fmt, "ciphertext")
        p = saes.decrypt(c, key)
        print(f"密钥   : {saes.to_bits(key, 16)} ({saes.to_hex(key, 16)})")
        print(f"密文 C : {saes.to_bits(c, 16)} ({saes.to_hex(c, 16)})")
        print(f"明文 P : {saes.to_bits(p, 16)} ({saes.to_hex(p, 16)})")
        if args.trace:
            _, steps = saes.decrypt(c, key, trace=True)
            for name, st in steps:
                print(f"  [{name:>18}] {saes.to_bits(st, 16)}")
        return 0

    if args.cmd == "encrypt-ascii":
        key = fmt_key(args)
        c = saes.encrypt_ascii(args.text, key)
        print(f"密钥       : {saes.to_bits(key, 16)} ({saes.to_hex(key, 16)})")
        print(f"明文字符串 : {args.text!r}")
        print(f"密文字符串 : {c!r}  （乱码属正常现象）")
        return 0

    if args.cmd == "decrypt-ascii":
        key = fmt_key(args)
        p = saes.decrypt_ascii(args.text, key)
        print(f"密钥       : {saes.to_bits(key, 16)} ({saes.to_hex(key, 16)})")
        print(f"密文字符串 : {args.text!r}")
        print(f"明文字符串 : {p!r}")
        return 0

    if args.cmd in ("double-encrypt", "double-decrypt"):
        k32 = saes.parse_bits(args.key, 32, "key32") if fmt == "bin" else saes.parse_hex(args.key, 32, "key32")
        if args.cmd == "double-encrypt":
            p = parse_data16(args.plaintext, fmt, "plaintext")
            c = saes.double_encrypt(p, k32)
            print(f"32位密钥   : {saes.to_bits(k32, 32)} (K1={saes.to_hex(k32 >> 16, 16)}, K2={saes.to_hex(k32 & 0xFFFF, 16)})")
            print(f"明文 P     : {saes.to_bits(p, 16)}")
            print(f"密文 C     : {saes.to_bits(c, 16)} ({saes.to_hex(c, 16)})")
        else:
            c = parse_data16(args.ciphertext, fmt, "ciphertext")
            p = saes.double_decrypt(c, k32)
            print(f"32位密钥   : {saes.to_bits(k32, 32)} (K1={saes.to_hex(k32 >> 16, 16)}, K2={saes.to_hex(k32 & 0xFFFF, 16)})")
            print(f"密文 C     : {saes.to_bits(c, 16)}")
            print(f"明文 P     : {saes.to_bits(p, 16)} ({saes.to_hex(p, 16)})")
        return 0

    if args.cmd in ("triple-encrypt", "triple-decrypt"):
        is_encrypt = args.cmd == "triple-encrypt"
        if args.mode == "ede":
            k32 = saes.parse_bits(args.key, 32, "key32") if fmt == "bin" else saes.parse_hex(args.key, 32, "key32")
            fn = saes.triple_encrypt_ede if is_encrypt else saes.triple_decrypt_ede
            data = parse_data16(args.data, fmt,
                                "plaintext" if is_encrypt else "ciphertext")
            out = fn(data, k32)
            print(f"EDE 模式 32 位密钥: {saes.to_bits(k32, 32)} (K1={saes.to_hex(k32 >> 16, 16)}, K2={saes.to_hex(k32 & 0xFFFF, 16)})")
        else:
            k48 = saes.parse_bits(args.key, 48, "key48") if fmt == "bin" else saes.parse_hex(args.key, 48, "key48")
            fn = saes.triple_encrypt_eee if is_encrypt else saes.triple_decrypt_eee
            data = parse_data16(args.data, fmt,
                                "plaintext" if is_encrypt else "ciphertext")
            out = fn(data, k48)
            print(f"EEE 模式 48 位密钥: {saes.to_bits(k48, 48)} "
                  f"(K1={saes.to_hex(k48 >> 32, 16)}, K2={saes.to_hex((k48 >> 16) & 0xFFFF, 16)}, K3={saes.to_hex(k48 & 0xFFFF, 16)})")
        tag = "密文 C" if is_encrypt else "明文 P"
        src = "明文 P" if is_encrypt else "密文 C"
        print(f"{src} : {saes.to_bits(data, 16)}")
        print(f"{tag} : {saes.to_bits(out, 16)} ({saes.to_hex(out, 16)})")
        return 0

    if args.cmd == "mitm":
        p0 = saes.parse_bits(args.ptext, 16, "plaintext")
        c0 = saes.parse_bits(args.ctext, 16, "ciphertext")
        pairs = [(p0, c0)]
        if args.ptext2 or args.ctext2:
            if not (args.ptext2 and args.ctext2):
                print("错误：-p2 与 -c2 必须同时提供", file=sys.stderr)
                return 2
            pairs.append((saes.parse_bits(args.ptext2, 16, "plaintext2"),
                          saes.parse_bits(args.ctext2, 16, "ciphertext2")))
        print(f"已知明密文对 {len(pairs)} 组，开始中间相遇攻击 ...")
        import time
        t0 = time.perf_counter()
        found = saes.meet_in_the_middle(pairs)
        dt = time.perf_counter() - t0
        print(f"攻击耗时 {dt:.3f} 秒，找到 {len(found)} 组候选密钥：")
        for k1, k2 in found:
            k32 = (k1 << 16) | k2
            print(f"  K1={saes.to_bits(k1, 16)} ({saes.to_hex(k1, 16)}), "
                  f"K2={saes.to_bits(k2, 16)} ({saes.to_hex(k2, 16)}) -> "
                  f"32位密钥 {saes.to_bits(k32, 32)}")
        if len(found) != 1:
            print("提示：候选密钥多于 1 组，请增加更多明密文对（第二/第三组）以唯一确定密钥。")
        return 0

    if args.cmd == "vectors":
        print("标准交叉测试向量（与所有按标准实现的小组一致）")
        print("=" * 64)
        vectors = [
            (0x6F6B, 0xA73B),   # 经典教材向量
            (0x0000, 0x0000),
            (0xFFFF, 0xFFFF),
            (0x0123, 0x4567),
            (0xABCD, 0xEF01),
        ]
        for p, k in vectors:
            c = saes.encrypt(p, k)
            assert saes.decrypt(c, k) == p
            print(f"P={saes.to_bits(p, 16)} ({saes.to_hex(p, 16)})  "
                  f"K={saes.to_bits(k, 16)} ({saes.to_hex(k, 16)})  "
                  f"-> C={saes.to_bits(c, 16)} ({saes.to_hex(c, 16)})")
        print("\nASCII 串示例（密钥 0x3A94）:")
        k = 0x3A94
        for t in ("Hello", "S-AES 123"):
            c = saes.encrypt_ascii(t, k)
            r = saes.decrypt_ascii(c, k)
            print(f"  {t!r} -> {c!r} -> {r!r}")
        return 0

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as e:
        print(f"输入错误：{e}", file=sys.stderr)
        sys.exit(2)
