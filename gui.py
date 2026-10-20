# -*- coding: utf-8 -*-
"""
S-AES 图形界面（Streamlit）
===========================

运行方式：
    streamlit run gui.py

包含全部四个关卡：
  第1关 基本测试：16 位明文/密钥加解密（支持二进制与十六进制，可查看中间状态）
  第2关 交叉测试：标准测试向量生成与比对
  第3关 扩展功能：ASCII 字符串分组加解密
  第4关 多重加密：双重加密、中间相遇攻击、三重加密（EDE/EEE）
"""

from __future__ import annotations

import time

import streamlit as st

import saes

st.set_page_config(page_title="S-AES 加解密系统", page_icon="🔐", layout="wide")

st.title("🔐 S-AES 简化高级加密标准")
st.caption("16 位分组 · 16 位基本密钥 · 信息安全导论课程作业 ｜ 本系统同时支持加密与解密交互")


# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------

def bits_or_hex(value: int, width: int) -> str:
    return f"`{saes.to_bits(value, width)}` (hex: `{saes.to_hex(value, width)}`)"


def parse_key(s: str) -> int:
    s = "".join(s.split())
    if s.startswith("0x"):
        return saes.parse_hex(s, 16, "密钥")
    if all(c in "01" for c in s) and s:
        return saes.parse_bits(s, 16, "密钥")
    if all(c in "0123456789abcdefABCDEF" for c in s) and s:
        return saes.parse_hex(s, 16, "密钥")
    raise ValueError("密钥格式无法识别，请输入 16 位二进制或 4 位十六进制")


def parse_data16(s: str, name: str) -> int:
    s = "".join(s.split())
    if s.startswith("0x"):
        return saes.parse_hex(s, 16, name)
    if all(c in "01" for c in s) and s:
        return saes.parse_bits(s, 16, name)
    if all(c in "0123456789abcdefABCDEF" for c in s) and s:
        return saes.parse_hex(s, 16, name)
    raise ValueError(f"{name}格式无法识别，请输入 16 位二进制或 4 位十六进制")


def parse_long_key(s: str, width: int) -> int:
    s = "".join(s.split())
    if s.startswith("0x"):
        return saes.parse_hex(s, width, "密钥")
    if all(c in "01" for c in s) and s:
        return saes.parse_bits(s, width, "密钥")
    if all(c in "0123456789abcdefABCDEF" for c in s) and s:
        return saes.parse_hex(s, width, "密钥")
    raise ValueError(f"密钥格式无法识别，请输入 {width} 位二进制或 {width // 4} 位十六进制")


def show_trace(steps):
    st.markdown("**中间过程**")
    rows = [{"步骤": name, "状态(二进制)": saes.to_bits(v, 16), "hex": saes.to_hex(v, 16)}
            for name, v in steps]
    st.dataframe(rows, hide_index=True, use_container_width=True)


# ----------------------------------------------------------------------------
# 侧边栏：算法说明
# ----------------------------------------------------------------------------

with st.sidebar:
    st.header("算法规格速览")
    st.markdown(
        """
- **分组**：16 bit（4 个半字节 n0n1n2n3，列填充 2×2 状态阵）
- **密钥**：16 bit，扩展为 K0、K1、K2 三把轮密钥
- **S 盒**：9 4 A B / D 1 8 5 / 6 2 0 3 / C E F 7
- **列混淆**：矩阵 [1 4; 4 1]，GF(2⁴) 模 x⁴+x+1
- **加密流程**：
  AK(K0) → NS→SR→MC→AK(K1) → NS→SR→AK(K2)
        """
    )
    st.divider()
    st.markdown("**交叉测试基准向量**")
    st.code("P=0x6F6B, K=0xA73B\n→ C=0x0067", language="text")

# ----------------------------------------------------------------------------
# 第 1 关：基本测试
# ----------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(
    ["第1关 基本测试", "第2关 交叉测试", "第3关 ASCII 串", "第4关 多重加密"])

with tab1:
    st.subheader("16 位数据加解密")
    c1, c2 = st.columns(2)
    with c1:
        key_str = st.text_input("密钥（16 位二进制 或 4 位十六进制）", "1010011100111011")
        pt_str = st.text_input("明文 P（16 位）", "0110111101101011")
        if st.button("🔒 加密", use_container_width=True):
            try:
                k = parse_key(key_str)
                p = parse_data16(pt_str, "明文")
                c, steps = saes.encrypt(p, k, trace=True)
                st.success(f"密文 C = {saes.to_bits(c, 16)}　(hex: {saes.to_hex(c, 16)})")
                show_trace(steps)
            except ValueError as e:
                st.error(f"输入错误：{e}")
    with c2:
        ct_str = st.text_input("密文 C（16 位）", "0000000001100111")
        if st.button("🔓 解密", use_container_width=True):
            try:
                k = parse_key(key_str)
                c = parse_data16(ct_str, "密文")
                p, steps = saes.decrypt(c, k, trace=True)
                st.success(f"明文 P = {saes.to_bits(p, 16)}　(hex: {saes.to_hex(p, 16)})")
                show_trace(steps)
            except ValueError as e:
                st.error(f"输入错误：{e}")

# ----------------------------------------------------------------------------
# 第 2 关：交叉测试
# ----------------------------------------------------------------------------
with tab2:
    st.subheader("标准测试向量（与其他小组程序交叉比对）")
    st.markdown(
        "所有按标准 S-AES 规格实现的程序，对相同明文 P 与密钥 K 必须得到相同密文 C；"
        "对本表任一密文 C 用相同 K 解密必须还原 P。请将本表结果与其他小组比对。")
    n_vec = st.slider("随机向量数量", 3, 20, 8)
    if st.button("🎲 生成测试向量表"):
        st.session_state["vectors"] = [
            (0x6F6B, 0xA73B),
            (0x0000, 0x0000),
            (0xFFFF, 0xFFFF),
        ] + [
            ((i * 0x9E3779B9 >> 8) & 0xFFFF, (i * 0x85EBCA6B >> 4) & 0xFFFF)
            for i in range(1, n_vec - 2)
        ]
    rows = []
    for p, k in st.session_state.get("vectors", [(0x6F6B, 0xA73B), (0x0000, 0x0000), (0xFFFF, 0xFFFF)]):
        c = saes.encrypt(p, k)
        ok = saes.decrypt(c, k) == p
        rows.append({
            "明文 P (bin)": saes.to_bits(p, 16), "密钥 K (bin)": saes.to_bits(k, 16),
            "密文 C (bin)": saes.to_bits(c, 16),
            "P(hex)": saes.to_hex(p, 16), "K(hex)": saes.to_hex(k, 16), "C(hex)": saes.to_hex(c, 16),
            "解密还原": "✅" if ok else "❌",
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)

# ----------------------------------------------------------------------------
# 第 3 关：ASCII 字符串
# ----------------------------------------------------------------------------
with tab3:
    st.subheader("ASCII 字符串加解密（每分组 2 字节）")
    key3 = st.text_input("密钥（16 位）", "0011101010010100", key="ascii_key")
    col1, col2 = st.columns(2)
    with col1:
        text_pt = st.text_area("明文字符串", "Hello, S-AES!")
        if st.button("🔒 加密字符串", use_container_width=True):
            try:
                k = parse_key(key3)
                c = saes.encrypt_ascii(text_pt, k)
                st.markdown("**密文字符串（乱码属正常）**")
                st.code(c, language="text")
                st.session_state["last_ascii_ct"] = c
            except ValueError as e:
                st.error(f"输入错误：{e}")
    with col2:
        text_ct = st.text_area("密文字符串（可为乱码，需按 latin-1 字符粘贴）",
                               st.session_state.get("last_ascii_ct", ""), key="ascii_ct")
        if st.button("🔓 解密字符串", use_container_width=True):
            try:
                k = parse_key(key3)
                p = saes.decrypt_ascii(text_ct, k)
                st.success(f"明文字符串：{p}")
            except ValueError as e:
                st.error(f"输入错误：{e}")
    st.info("说明：明文按 UTF-8 编码、2 字节一组加密，PKCS#7 填充；密文以 latin-1 字符呈现（每个字节对应一个字符），因此通常显示为乱码，但可无损复制还原。")

# ----------------------------------------------------------------------------
# 第 4 关：多重加密
# ----------------------------------------------------------------------------
with tab4:
    st.subheader("4.1 双重加密（32 位密钥 K1‖K2）")
    d1, d2 = st.columns(2)
    key32_str = st.text_input("32 位密钥（K1 16 位 ‖ K2 16 位）", "10100111001110110110111101101011")
    with d1:
        p4 = st.text_input("明文 P（16 位）", "0110111101101011", key="p4")
        if st.button("🔒 双重加密", use_container_width=True):
            try:
                k32 = parse_long_key(key32_str, 32)
                p = parse_data16(p4, "明文")
                c = saes.double_encrypt(p, k32)
                st.markdown(f"- K1 = {saes.to_bits(k32 >> 16, 16)}，K2 = {saes.to_bits(k32 & 0xFFFF, 16)}")
                st.success(f"密文 C = {saes.to_bits(c, 16)} (hex {saes.to_hex(c, 16)})")
            except ValueError as e:
                st.error(f"输入错误：{e}")
    with d2:
        c4 = st.text_input("密文 C（16 位）", "", key="c4")
        if st.button("🔓 双重解密", use_container_width=True):
            try:
                k32 = parse_long_key(key32_str, 32)
                c = parse_data16(c4, "密文")
                p = saes.double_decrypt(c, k32)
                st.success(f"明文 P = {saes.to_bits(p, 16)} (hex {saes.to_hex(p, 16)})")
            except ValueError as e:
                st.error(f"输入错误：{e}")

    st.divider()
    st.subheader("4.2 中间相遇攻击")
    st.markdown("已知同一 32 位密钥下的明密文对，攻击复杂度约 2¹⁷ 次（对比暴力搜索 2³²）。"
                "误匹配候选随明密文对数量增加而锐减：单组约 2¹⁶ 个，两组后通常所剩无几，三组即可唯一确定。")
    m1, m2 = st.columns(2)
    with m1:
        mp1 = st.text_input("明文 P₁（16 位二进制）", "0110111101101011", key="mp1")
        mc1 = st.text_input("密文 C₁（16 位二进制）", "1000000110010011", key="mc1")
    with m2:
        mp2 = st.text_input("明文 P₂（可选）", "1011101101010001", key="mp2")
        mc2 = st.text_input("密文 C₂（可选）", "0000100101010100", key="mc2")
    use_second = st.checkbox("使用第二组明密文对（唯一确定密钥）", value=True)
    if st.button("⚡ 执行中间相遇攻击", use_container_width=True):
        try:
            pairs = [(saes.parse_bits(mp1, 16, "P1"), saes.parse_bits(mc1, 16, "C1"))]
            if use_second:
                pairs.append((saes.parse_bits(mp2, 16, "P2"), saes.parse_bits(mc2, 16, "C2")))
            t0 = time.perf_counter()
            found = saes.meet_in_the_middle(pairs)
            dt = time.perf_counter() - t0
            st.success(f"攻击完成，耗时 {dt:.3f} 秒，找到 {len(found)} 组候选密钥")
            for k1, k2 in found:
                k32 = (k1 << 16) | k2
                st.markdown(
                    f"- K1 = `{saes.to_bits(k1, 16)}`，K2 = `{saes.to_bits(k2, 16)}` "
                    f"→ 32 位密钥 `{saes.to_bits(k32, 32)}`")
            if len(found) != 1:
                st.warning(f"候选密钥多于 1 组（共 {len(found)} 组）：可再提供一组明密文对进一步过滤，"
                           "或核对密文是否输入正确。")
        except ValueError as e:
            st.error(f"输入错误：{e}")

    st.divider()
    st.subheader("4.3 三重加密")
    t1, t2 = st.columns(2)
    with t1:
        st.markdown("**方案一：32 位密钥 EDE 模式**（C = E_K1(D_K2(E_K1(P)))，类比 2 密钥 3DES）")
        key_ede = st.text_input("32 位密钥", "10100111001110110110111101101011", key="kede")
        p_ede = st.text_input("明文 P（16 位）", "0110111101101011", key="pede")
        if st.button("🔒 EDE 加密", use_container_width=True):
            try:
                k32 = parse_long_key(key_ede, 32)
                p = parse_data16(p_ede, "明文")
                c = saes.triple_encrypt_ede(p, k32)
                st.success(f"密文 C = {saes.to_bits(c, 16)} (hex {saes.to_hex(c, 16)})")
                st.session_state["ede_c"] = saes.to_bits(c, 16)
            except ValueError as e:
                st.error(f"输入错误：{e}")
        c_ede = st.text_input("密文 C（16 位）", st.session_state.get("ede_c", ""), key="cede")
        if st.button("🔓 EDE 解密", use_container_width=True):
            try:
                k32 = parse_long_key(key_ede, 32)
                c = parse_data16(c_ede, "密文")
                p = saes.triple_decrypt_ede(c, k32)
                st.success(f"明文 P = {saes.to_bits(p, 16)} (hex {saes.to_hex(p, 16)})")
            except ValueError as e:
                st.error(f"输入错误：{e}")
    with t2:
        st.markdown("**方案二：48 位密钥 EEE 模式**（C = E_K3(E_K2(E_K1(P)))）")
        key_eee = st.text_input("48 位密钥（K1‖K2‖K3）",
                                "1010011100111011" + "0110111101101011" + "0011101010010100", key="keee")
        p_eee = st.text_input("明文 P（16 位）", "0110111101101011", key="peee")
        if st.button("🔒 EEE 加密", use_container_width=True):
            try:
                k48 = parse_long_key(key_eee, 48)
                p = parse_data16(p_eee, "明文")
                c = saes.triple_encrypt_eee(p, k48)
                st.success(f"密文 C = {saes.to_bits(c, 16)} (hex {saes.to_hex(c, 16)})")
                st.session_state["eee_c"] = saes.to_bits(c, 16)
            except ValueError as e:
                st.error(f"输入错误：{e}")
        c_eee = st.text_input("密文 C（16 位）", st.session_state.get("eee_c", ""), key="ceee")
        if st.button("🔓 EEE 解密", use_container_width=True):
            try:
                k48 = parse_long_key(key_eee, 48)
                c = parse_data16(c_eee, "密文")
                p = saes.triple_decrypt_eee(c, k48)
                st.success(f"明文 P = {saes.to_bits(p, 16)} (hex {saes.to_hex(p, 16)})")
            except ValueError as e:
                st.error(f"输入错误：{e}")

st.divider()
st.caption("实现遵循 Musa, Schaefer & Wedig《A Simplified AES Algorithm》标准规格，详见 docs/开发手册.md")
