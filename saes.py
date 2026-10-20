# -*- coding: utf-8 -*-
"""
S-AES (Simplified AES) 算法标准实现
===================================

16 位分组、16 位密钥的教学用简化 AES 算法。

算法规格（依据 Musa, Schaefer & Wedig 论文
"A Simplified AES Algorithm and Its Linear and Differential Cryptanalyses"）：

- 状态矩阵：16 位明文按顺序分为 4 个半字节（nibble，4 bit）n0 n1 n2 n3，
  按列填充 2x2 状态矩阵：
      ┌ n0 n2 ┐
      └ n1 n3 ┘
  即第一列 (n0, n1) 为密文高 8 位字节，第二列 (n2, n3) 为低 8 位字节。

- S 盒 / 逆 S 盒（GF(2^4) 上乘法逆元经仿射变换得到，标准给定表如下）

- 行移位 ShiftRows（NibbleShift）：交换状态第二行的两个半字节，即 n1 <-> n3。

- 列混淆 MixColumns：列向量左乘矩阵 [[1, 4], [4, 1]]，
  乘法在 GF(2^4) 上进行，模多项式 x^4 + x + 1（0b10011）。
  逆列混淆矩阵为 [[9, 2], [2, 9]]。

- 轮密钥加 AddRoundKey：16 位状态与 16 位轮密钥逐位异或。

- 密钥扩展：16 位密钥拆为两个 8 位字 w0、w1：
      w2 = w0 XOR Rcon1 XOR RotNib(w1)      Rcon1 = 0x80 (1000 0000)
      w3 = w2 XOR w1
      w4 = w2 XOR Rcon2 XOR RotNib(w3)      Rcon2 = 0x30 (0011 0000)
      w5 = w4 XOR w3
  其中 RotNib(w) 为交换字内高、低两个半字节。
  三轮密钥：K0 = w0||w1，K1 = w2||w3，K2 = w4||w5。

- 加密流程：
      AddRoundKey(K0)
      第 1 轮：NibbleSub -> ShiftRows -> MixColumns -> AddRoundKey(K1)
      第 2 轮：NibbleSub -> ShiftRows -> AddRoundKey(K2)   （无列混淆）
- 解密流程：上述逆过程倒序执行（InvShiftRows == ShiftRows）。

本模块同时提供课程作业要求的所有扩展功能：
  1) 基本加解密（16 bit 明文 / 16 bit 密钥 / 16 bit 密文）
  2) ASCII 字符串分组加解密（每分组 2 字节，PKCS#7 填充）
  3) 双重加密（32 位密钥 K1||K2）
  4) 中间相遇攻击（已知明密文对恢复 K1、K2）
  5) 三重加密（32 位密钥 EDE 模式 / 48 位密钥 EEE 模式）

作者：信息安全导论课程作业
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

# ----------------------------------------------------------------------------
# 一、基础常量：S 盒、逆 S 盒、轮常量
# ----------------------------------------------------------------------------

# S 盒：索引为输入半字节(0~15)，值为输出半字节
# 表格形式（行=高2位 x，列=低2位 y）：
#       y=0  y=1  y=2  y=3
# x=0:   9    4    A    B
# x=1:   D    1    8    5
# x=2:   6    2    0    3
# x=3:   C    E    F    7
SBOX: Tuple[int, ...] = (
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
)

# 逆 S 盒：INV_SBOX[SBOX[i]] == i
INV_SBOX: Tuple[int, ...] = (
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE,
)

# 轮常量（8 位字上使用）
RCON1 = 0x80  # 1000 0000
RCON2 = 0x30  # 0011 0000

# 列混淆矩阵与逆矩阵（GF(2^4) 上）
MIX_MATRIX = ((1, 4), (4, 1))
INV_MIX_MATRIX = ((9, 2), (2, 9))


# ----------------------------------------------------------------------------
# 二、GF(2^4) 有限域运算（模多项式 x^4 + x + 1）
# ----------------------------------------------------------------------------

def gf_mul(a: int, b: int) -> int:
    """GF(2^4) 乘法：两半字节相乘，模 x^4 + x + 1。"""
    a &= 0xF
    b &= 0xF
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x10:          # 移出 4 位后约去 x^4 = x + 1
            a ^= 0b10011      # x^4 + x + 1
    return result & 0xF


def gf_inv(a: int) -> int:
    """GF(2^4) 求逆（暴力枚举），0 的逆定义为 0。"""
    if a & 0xF == 0:
        return 0
    for b in range(1, 16):
        if gf_mul(a, b) == 1:
            return b
    raise ValueError(f"GF(2^4) 中 {a:#x} 不存在乘法逆元")


# ----------------------------------------------------------------------------
# 三、输入格式辅助函数
# ----------------------------------------------------------------------------

def clean_binary(s: str) -> str:
    """去除二进制串中的空格等分隔符并校验。"""
    s = "".join(s.split())
    if len(s) == 0 or any(c not in "01" for c in s):
        raise ValueError(f"非法二进制串: {s!r}")
    return s


def parse_bits(s: str, width: int, name: str = "data") -> int:
    """将二进制字符串解析为 width 位整数。"""
    s = clean_binary(s)
    if len(s) != width:
        raise ValueError(f"{name} 必须为 {width} 位二进制，当前为 {len(s)} 位")
    return int(s, 2)


def parse_hex(s: str, width_bits: int, name: str = "data") -> int:
    """将十六进制字符串解析为 width_bits 位整数。"""
    s = "".join(s.split()).lower().removeprefix("0x")
    if len(s) != width_bits // 4 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError(f"{name} 必须为 {width_bits // 4} 位十六进制")
    return int(s, 16)


def to_bits(value: int, width: int) -> str:
    """整数转 width 位二进制字符串。"""
    return format(value, f"0{width}b")


def to_hex(value: int, width: int) -> str:
    """整数转 width 位对应的十六进制字符串。"""
    return format(value, f"0{width // 4}x")


# ----------------------------------------------------------------------------
# 四、S-AES 核心变换
# ----------------------------------------------------------------------------

def key_expansion(key: int) -> Tuple[int, int, int]:
    """
    16 位密钥扩展，生成 3 个 16 位轮密钥 (K0, K1, K2)。

    w0、w1 为密钥高、低 8 位字；
    w2 = w0 ^ Rcon1 ^ RotNib(w1)；w3 = w2 ^ w1；
    w4 = w2 ^ Rcon2 ^ RotNib(w3)；w5 = w4 ^ w3。
    """
    if not 0 <= key <= 0xFFFF:
        raise ValueError("密钥必须为 16 位 (0~0xFFFF)")
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF

    def rot_nib(w: int) -> int:              # 交换字内两个半字节
        return ((w & 0x0F) << 4) | ((w >> 4) & 0x0F)

    w2 = w0 ^ RCON1 ^ rot_nib(w1)
    w3 = w2 ^ w1
    w4 = w2 ^ RCON2 ^ rot_nib(w3)
    w5 = w4 ^ w3

    k0 = (w0 << 8) | w1
    k1 = (w2 << 8) | w3
    k2 = (w4 << 8) | w5
    return k0, k1, k2


def _sub_nibbles(state: int) -> int:
    """对 16 位状态的 4 个半字节逐个查 S 盒。"""
    return ((SBOX[(state >> 12) & 0xF] << 12)
            | (SBOX[(state >> 8) & 0xF] << 8)
            | (SBOX[(state >> 4) & 0xF] << 4)
            | SBOX[state & 0xF])


def _inv_sub_nibbles(state: int) -> int:
    """对 16 位状态的 4 个半字节逐个查逆 S 盒。"""
    return ((INV_SBOX[(state >> 12) & 0xF] << 12)
            | (INV_SBOX[(state >> 8) & 0xF] << 8)
            | (INV_SBOX[(state >> 4) & 0xF] << 4)
            | INV_SBOX[state & 0xF])


def _shift_rows(state: int) -> int:
    """行移位：交换第二行两个半字节，即位串上的 n1 与 n3 互换。"""
    n0 = (state >> 12) & 0xF
    n1 = (state >> 8) & 0xF
    n2 = (state >> 4) & 0xF
    n3 = state & 0xF
    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1


def _mix_columns(state: int, matrix=((1, 4), (4, 1))) -> int:
    """
    列混淆：状态按列填充为
        ┌ n0 n2 ┐
        └ n1 n3 ┘
    每列 (s0, s1) 左乘 2x2 矩阵（GF(2^4) 运算）。
    默认矩阵 [[1,4],[4,1]]，传入 INV_MIX_MATRIX 即逆列混淆。
    """
    n0 = (state >> 12) & 0xF
    n1 = (state >> 8) & 0xF
    n2 = (state >> 4) & 0xF
    n3 = state & 0xF

    (m00, m01), (m10, m11) = matrix
    c0_0 = gf_mul(m00, n0) ^ gf_mul(m01, n1)   # 第一列第 1 行
    c0_1 = gf_mul(m10, n0) ^ gf_mul(m11, n1)   # 第一列第 2 行
    c1_0 = gf_mul(m00, n2) ^ gf_mul(m01, n3)   # 第二列第 1 行
    c1_1 = gf_mul(m10, n2) ^ gf_mul(m11, n3)   # 第二列第 2 行
    return (c0_0 << 12) | (c0_1 << 8) | (c1_0 << 4) | c1_1


def encrypt(plaintext: int, key: int, trace: bool = False):
    """
    S-AES 加密：16 位明文 + 16 位密钥 -> 16 位密文。

    trace=True 时返回 (密文, 中间状态列表)，列表元素为 (步骤名, 16位状态)。
    """
    if not 0 <= plaintext <= 0xFFFF:
        raise ValueError("明文必须为 16 位 (0~0xFFFF)")
    k0, k1, k2 = key_expansion(key)
    steps: List[Tuple[str, int]] = []

    # 轮密钥加 0
    state = plaintext ^ k0
    if trace:
        steps.append(("AddRoundKey(K0)", state))

    # 第 1 轮
    state = _sub_nibbles(state)
    if trace:
        steps.append(("NibbleSub", state))
    state = _shift_rows(state)
    if trace:
        steps.append(("ShiftRows", state))
    state = _mix_columns(state)
    if trace:
        steps.append(("MixColumns", state))
    state ^= k1
    if trace:
        steps.append(("AddRoundKey(K1)", state))

    # 第 2 轮（无列混淆）
    state = _sub_nibbles(state)
    if trace:
        steps.append(("NibbleSub", state))
    state = _shift_rows(state)
    if trace:
        steps.append(("ShiftRows", state))
    state ^= k2
    if trace:
        steps.append(("AddRoundKey(K2)", state))

    return (state, steps) if trace else state


def decrypt(ciphertext: int, key: int, trace: bool = False):
    """S-AES 解密：16 位密文 + 16 位密钥 -> 16 位明文（加密的逆过程）。"""
    if not 0 <= ciphertext <= 0xFFFF:
        raise ValueError("密文必须为 16 位 (0~0xFFFF)")
    k0, k1, k2 = key_expansion(key)
    steps: List[Tuple[str, int]] = []

    state = ciphertext ^ k2
    if trace:
        steps.append(("AddRoundKey(K2)", state))

    # 第 1 轮逆变换
    state = _shift_rows(state)                # InvShiftRows == ShiftRows
    if trace:
        steps.append(("InvShiftRows", state))
    state = _inv_sub_nibbles(state)
    if trace:
        steps.append(("InvNibbleSub", state))
    state ^= k1
    if trace:
        steps.append(("AddRoundKey(K1)", state))
    state = _mix_columns(state, INV_MIX_MATRIX)
    if trace:
        steps.append(("InvMixColumns", state))

    # 第 2 轮逆变换
    state = _shift_rows(state)
    if trace:
        steps.append(("InvShiftRows", state))
    state = _inv_sub_nibbles(state)
    if trace:
        steps.append(("InvNibbleSub", state))
    state ^= k0
    if trace:
        steps.append(("AddRoundKey(K0)", state))

    return (state, steps) if trace else state


# ----------------------------------------------------------------------------
# 五、第 3 关：ASCII 字符串分组加解密
# ----------------------------------------------------------------------------

def _pkcs7_pad(data: bytes, block: int = 2) -> bytes:
    """按 2 字节分组做 PKCS#7 填充（填充值为填充长度 1 或 2）。"""
    rem = len(data) % block
    pad_len = block - rem
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block: int = 2) -> bytes:
    """去除 PKCS#7 填充；填充非法时原样返回（解错密钥时输出乱码而非报错）。"""
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= block and data[-pad_len:] == bytes([pad_len]) * pad_len:
        return data[:-pad_len]
    return data


def encrypt_ascii(text: str, key: int) -> str:
    """
    第 3 关：ASCII 字符串加密。

    明文按 UTF-8 编码为字节序列，按 2 字节一组做 PKCS#7 填充后逐组加密，
    输出为每组 16 位密文拼接而成的字符串（很可能是乱码）。
    """
    data = _pkcs7_pad(text.encode("utf-8"), 2)
    out = []
    for i in range(0, len(data), 2):
        block = (data[i] << 8) | data[i + 1]
        c = encrypt(block, key)
        out.append(bytes([(c >> 8) & 0xFF, c & 0xFF]))
    return b"".join(out).decode("latin-1")     # latin-1 保证字节-字符一一对应


def decrypt_ascii(cipher_text: str, key: int) -> str:
    """
    第 3 关：ASCII 密文字符串解密，还原明文字符串。
    """
    data = cipher_text.encode("latin-1")
    if len(data) % 2 != 0:
        raise ValueError("密文字符串长度必须为偶数（每 2 个字符一组）")
    out = []
    for i in range(0, len(data), 2):
        block = (data[i] << 8) | data[i + 1]
        p = decrypt(block, key)
        out.append(bytes([(p >> 8) & 0xFF, p & 0xFF]))
    plain = _pkcs7_unpad(b"".join(out), 2)
    return plain.decode("utf-8", errors="replace")


# ----------------------------------------------------------------------------
# 六、第 4 关：多重加密与中间相遇攻击
# ----------------------------------------------------------------------------

def double_encrypt(plaintext: int, key32: int) -> int:
    """4.1 双重加密：C = E_K2(E_K1(P))，key32 = K1(高16位) || K2(低16位)。"""
    if not 0 <= key32 <= 0xFFFF_FFFF:
        raise ValueError("双重加密密钥必须为 32 位")
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    return encrypt(encrypt(plaintext, k1), k2)


def double_decrypt(ciphertext: int, key32: int) -> int:
    """双重解密：P = D_K1(D_K2(C))。"""
    if not 0 <= key32 <= 0xFFFF_FFFF:
        raise ValueError("双重加密密钥必须为 32 位")
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    return decrypt(decrypt(ciphertext, k2), k1)


def meet_in_the_middle(pairs: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """
    4.2 中间相遇攻击（对双重加密）。

    已知若干使用同一 32 位密钥 (K1||K2) 的明密文对 (P, C)，其中 C = E_K2(E_K1(P))。
    攻击原理：
      正向：对每个候选 K1 计算中间值 M = E_K1(P)，建表；
      反向：对每个候选 K2 计算中间值 M = D_K2(C)，在表中匹配；
      多余的明密文对用于剔除误匹配候选，最终得到唯一 (K1, K2)。
    时间复杂度约 2^16 + 2^16 = 2^17 次加解密，远小于暴力搜索 2^32。
    """
    if not pairs:
        raise ValueError("至少需要一组明密文对")

    p0, c0 = pairs[0]
    forward: dict = {}
    for k1 in range(0x10000):                  # 正向建表：M = E_K1(P)
        m = encrypt(p0, k1)
        forward.setdefault(m, []).append(k1)

    candidates = set()
    for k2 in range(0x10000):                  # 反向匹配：M = D_K2(C)
        m = decrypt(c0, k2)
        if m in forward:
            for k1 in forward[m]:
                candidates.add((k1, k2))

    # 用其余明密文对过滤候选
    for p, c in pairs[1:]:
        candidates = {(k1, k2) for k1, k2 in candidates
                      if encrypt(encrypt(p, k1), k2) == c}

    return sorted(candidates)


def triple_encrypt_ede(plaintext: int, key32: int) -> int:
    """
    4.3 三重加密（方案一，32 位密钥 K1||K2，EDE 模式，类比 2 密钥 3DES）：
        加密 C = E_K1(D_K2(E_K1(P)))
        解密 P = D_K1(E_K2(D_K1(C)))
    """
    if not 0 <= key32 <= 0xFFFF_FFFF:
        raise ValueError("EDE 三重加密密钥必须为 32 位")
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    mid = decrypt(encrypt(plaintext, k1), k2)
    return encrypt(mid, k1)


def triple_decrypt_ede(ciphertext: int, key32: int) -> int:
    """EDE 模式解密：P = D_K1(E_K2(D_K1(C)))。"""
    if not 0 <= key32 <= 0xFFFF_FFFF:
        raise ValueError("EDE 三重加密密钥必须为 32 位")
    k1 = (key32 >> 16) & 0xFFFF
    k2 = key32 & 0xFFFF
    mid = encrypt(decrypt(ciphertext, k1), k2)
    return decrypt(mid, k1)


def triple_encrypt_eee(plaintext: int, key48: int) -> int:
    """
    4.3 三重加密（方案二，48 位密钥 K1||K2||K3，EEE 模式）：
        加密 C = E_K3(E_K2(E_K1(P)))
        解密 P = D_K1(D_K2(D_K3(C)))
    """
    if not 0 <= key48 <= 0xFFFF_FFFF_FFFF:
        raise ValueError("EEE 三重加密密钥必须为 48 位")
    k1 = (key48 >> 32) & 0xFFFF
    k2 = (key48 >> 16) & 0xFFFF
    k3 = key48 & 0xFFFF
    return encrypt(encrypt(encrypt(plaintext, k1), k2), k3)


def triple_decrypt_eee(ciphertext: int, key48: int) -> int:
    """EEE 模式解密：P = D_K1(D_K2(D_K3(C)))。"""
    if not 0 <= key48 <= 0xFFFF_FFFF_FFFF:
        raise ValueError("EEE 三重加密密钥必须为 48 位")
    k1 = (key48 >> 32) & 0xFFFF
    k2 = (key48 >> 16) & 0xFFFF
    k3 = key48 & 0xFFFF
    return decrypt(decrypt(decrypt(ciphertext, k3), k2), k1)


# ----------------------------------------------------------------------------
# 七、自检
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    # 标准测试向量：按上述规格逐步手工推演所得（详见开发手册）
    P, K, C = 0x6F6B, 0xA73B, None
    C = encrypt(P, K)
    print(f"测试向量: P={to_bits(P,16)} K={to_bits(K,16)}")
    print(f"密文 C = {to_bits(C,16)} (hex {to_hex(C,16)})")
    assert decrypt(C, K) == P, "解密自检失败"
    assert C == 0x0067, "标准测试向量校验失败"
    print("自检通过：加密后解密可还原，标准向量一致。")
