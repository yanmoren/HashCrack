#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HashCrack 便携版打包脚本
========================

把 Flutter 编译产物和 runtime/（hashcat 内核 + Python 运行时 + 提取工具 +
字典）组装成一个完整的绿色便携目录，拷贝到任意 Windows 电脑双击即用。

用法:
    python scripts/build_portable.py              # 编译 + 打包
    python scripts/build_portable.py --skip-build # 只打包（已编译过）
    python scripts/build_portable.py --zip        # 打包后额外压缩成 ZIP

产物:
    dist/HashCrack/            便携目录（可直接拷贝或压缩分发）
    dist/HashCrack.zip         可选，压缩后的分发包
"""

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLUTTER = ROOT / "flutter_windows_3.47.3-stable" / "flutter" / "bin"
BUILD_OUT = ROOT / "build" / "windows" / "x64" / "runner" / "Release"
DIST = ROOT / "dist" / "HashCrack"
RUNTIME = ROOT / "runtime"

APP_NAME = "HashCrack.exe"

GUIDE = """HashCrack — hashcat 图形化破解工具
========================================

【怎么用】
1. 双击 HashCrack.exe 启动（无需安装，也不需要装 Python 或 hashcat）
2. 把加密文件拖进窗口，或点「选择文件」
3. 软件自动完成：识别类型 → 提取哈希 → 调用 hashcat 破解 → 显示明文密码
4. 解出来的密码可一键复制

【支持的文件】
  ZIP 压缩包          (*.zip)
  PDF 文档            (*.pdf)
  Office 2007+        (*.docx / *.xlsx / *.pptx)
  Office 97-2003      (*.doc / *.xls / *.ppt)
  WiFi 握手包         (*.cap / *.pcap / *.pcapng)
  纯哈希文本文件      (*.txt / *.hash)

【MIFARE 卡片分析器】
主界面上的「MIFARE 卡片分析器」是独立功能，不占显卡、不依赖 hashcat，
手机上单机也能用。把门禁卡转储拖进来即可（*.nfc / *.shd / *.eml / *.mfd / *.bin）：

  · 转储分析：讲明白这是什么卡、每个扇区的 Key A / Key B / 访问位、
    哪些密钥已知、哪些扇区读不出数据，并导出 Proxmark / Flipper 通用的密钥字典
  · 密钥恢复：导入 mfkey32 的 nonce 日志，纯离线算出未知密钥（约 1 秒）

两点必须知道：
  1) 转储文件本身没法离线「试」密钥 —— 里面只有明文，没有密文也没有 nonce，
     猜错了没有任何东西能告诉你错了。所以纯 dump 离线爆破不成立。
  2) Key A 在卡片设计上永远读不出来，dump 里的 ?? 是正常现象，不是文件坏了。

【常见问题】

Q: 提示「未找到可用的 OpenCL 运行环境」？
A: hashcat 靠显卡的 OpenCL 驱动做计算。请：
   1) 到 NVIDIA / AMD / Intel 官网装最新版显卡驱动
   2) 笔记本确认用独立显卡运行本软件
   3) 虚拟机里一般跑不了 OpenCL，需要物理机

Q: 破解很慢？
A: 破解速度取决于显卡性能。软件默认策略是「先跑字典，没中再逐级掩码
   （4 位数字 → 8 位数字 → 字母 → 全字符）」。想加快就换更好的显卡，
   或自己准备更精准的字典。

Q: 想用自己的字典？
A: 把 .txt 字典文件直接丢进本目录下的 runtime\\dicts 文件夹，
   重启软件就会自动加载，不用在界面里手动添加。

Q: 想换更新版本的 hashcat？
A: 替换 runtime\\hashcat 目录里的内容即可，或在「设置」里指定其他路径。

【目录说明】
  HashCrack.exe        主程序
  flutter_windows.dll  Flutter 运行库
  data\\                应用资源
  runtime\\hashcat\\     hashcat 内核（含全部哈希模式模块）
  runtime\\python\\      内置便携 Python（提取脚本运行时，无需系统安装）
  runtime\\tools\\       哈希提取工具（zip2john / pdf2john / office2john / hcxtools）
  runtime\\dicts\\       密码字典（可自行增删）

【免责声明】
本工具仅用于恢复自己遗忘的密码、授权的安全测试与教学用途。
请勿用于破解他人文件，否则后果自负。
"""


def log(msg):
    print(f"[build] {msg}", flush=True)


def run_flutter_build():
    """调用 Flutter 编译 Windows 发布版。"""
    log("开始编译 Flutter Windows 发布版（可能需要几分钟）...")
    env = os.environ.copy()
    env["PATH"] = str(FLUTTER) + os.pathsep + env.get("PATH", "")
    # Flutter 的 VS 探测依赖这个环境变量，某些 shell 下缺失会导致检测失败
    env.setdefault("ProgramFiles(x86)", r"C:\Program Files (x86)")

    exe = "flutter.bat" if os.name == "nt" else "flutter"
    cmd = [str(FLUTTER / exe), "build", "windows", "--release"]
    r = subprocess.run(cmd, cwd=str(ROOT), env=env,
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(r.stdout[-4000:])
        print(r.stderr[-4000:], file=sys.stderr)
        raise SystemExit("Flutter 编译失败")
    log("编译完成")


def find_app_exe():
    """在编译输出目录里找主程序 exe。"""
    for name in (APP_NAME, "hashcat_gui.exe"):
        p = BUILD_OUT / name
        if p.exists():
            return p
    raise SystemExit(f"未找到编译产物，请确认 {BUILD_OUT} 下有 exe 文件")


def assemble():
    """组装便携目录。"""
    if not BUILD_OUT.exists():
        raise SystemExit(f"编译输出目录不存在: {BUILD_OUT}\n请先运行编译。")

    if DIST.exists():
        log(f"清理旧产物 {DIST}")
        shutil.rmtree(DIST, ignore_errors=True)
    DIST.mkdir(parents=True, exist_ok=True)

    # 1) 主程序 + Flutter 运行库 + data 资源
    src_exe = find_app_exe()
    dst_exe = DIST / APP_NAME
    shutil.copy2(src_exe, dst_exe)
    log(f"主程序: {src_exe.name} -> {APP_NAME}")

    for item in BUILD_OUT.iterdir():
        if item.name == src_exe.name:
            continue
        if item.is_file():
            shutil.copy2(item, DIST / item.name)
        elif item.is_dir():
            shutil.copytree(item, DIST / item.name, dirs_exist_ok=True)
    log("Flutter 运行库与资源已复制")

    # 2) runtime 目录（hashcat 内核 / Python / 提取工具 / 字典）
    if not RUNTIME.exists():
        raise SystemExit(f"缺少 runtime 目录: {RUNTIME}")
    shutil.copytree(RUNTIME, DIST / "runtime", dirs_exist_ok=True)
    log("runtime 已复制（hashcat + Python + 提取工具 + 字典）")

    # 3) 使用说明
    guide_path = DIST / "使用说明.txt"
    guide_path.write_text(GUIDE, encoding="utf-8")
    log("使用说明已生成")

    # 4) 统计体积
    total = sum(f.stat().st_size for f in DIST.rglob("*") if f.is_file())
    count = sum(1 for f in DIST.rglob("*") if f.is_file())
    log(f"打包完成: {DIST}")
    log(f"  文件数 {count}，总体积 {total / 1024 / 1024:.1f} MB")
    return DIST


def verify(dist):
    """校验关键部件是否齐全。"""
    log("校验便携目录完整性...")
    checks = [
        ("主程序", dist / APP_NAME),
        ("hashcat 内核", dist / "runtime" / "hashcat" / "hashcat.exe"),
        ("Python 运行时", dist / "runtime" / "python" / "python.exe"),
        ("ZIP 提取器", dist / "runtime" / "tools" / "zip2john.py"),
        ("PDF 提取器", dist / "runtime" / "tools" / "pdf2john.py"),
        ("Office 提取器", dist / "runtime" / "tools" / "office2john.py"),
        ("WiFi 工具", dist / "runtime" / "tools" / "hcxtools" / "hcxpcapngtool.exe"),
        ("内置字典", dist / "runtime" / "dicts" / "common.txt"),
    ]
    ok = True
    for label, p in checks:
        mark = "OK " if p.exists() else "缺失"
        if not p.exists():
            ok = False
        print(f"  [{mark}] {label}")
    if not ok:
        print("  !! 存在缺失项，便携包可能不完整")
    return ok


def make_zip(dist):
    """压缩成 ZIP 分发包。"""
    zip_path = ROOT / "dist" / "HashCrack.zip"
    if zip_path.exists():
        zip_path.unlink()
    log(f"正在压缩 {zip_path.name}（文件较多，请耐心等待）...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for f in dist.rglob("*"):
            if f.is_file():
                z.write(f, f.relative_to(dist.parent))
    size = zip_path.stat().st_size / 1024 / 1024
    log(f"压缩完成: {zip_path}  ({size:.1f} MB)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true", help="跳过编译，只打包")
    ap.add_argument("--zip", action="store_true", help="打包后压缩成 ZIP")
    args = ap.parse_args()

    if not args.skip_build:
        run_flutter_build()
    dist = assemble()
    verify(dist)
    if args.zip:
        make_zip(dist)
    log("全部完成")


if __name__ == "__main__":
    main()
