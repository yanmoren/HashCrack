#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HashCrack 分发包打包脚本（电脑端 / 手机端布局）
==============================================

按现有发布布局组装 dist/，产出可直接分发的一整套：

    dist/
      电脑端/
        启动 HashCrack.bat
        HashCrack/
          HashCrack.exe            (由 hashcat_gui.exe 重命名而来)
          flutter_windows.dll
          desktop_drop_plugin.dll
          data/
          runtime/                 (hashcat + python + tools + dicts)
          使用说明.txt
      手机端/
        HashCrack.apk              (存在则同步，缺失则保留旧包)
      说明.txt
      HashCrack-电脑端.zip          (电脑端文件夹内容的压缩包)

用法:
    python scripts/build_dist.py                 # 编译 + 打包 + 压缩
    python scripts/build_dist.py --skip-build    # 跳过编译，只用现有产物打包
    python scripts/build_dist.py --skip-zip      # 打包但不压缩（省时间）
"""

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

# 注意：这里刻意不用 Path.resolve()——本机项目路径含中文（E:\临时文件\...），
# Windows 下 MSBuild 执行 tool_backend.bat 时会把中文路径毁成乱码导致编译失败。
# 因此通过 ASCII 目录联接（E:\hc_build）构建，abspath 不解析联接，路径保持 ASCII。
ROOT = Path(os.path.abspath(__file__)).parent.parent
FLUTTER_BIN = ROOT / "flutter_windows_3.47.3-stable" / "flutter" / "bin"
BUILD_OUT = ROOT / "build" / "windows" / "x64" / "runner" / "Release"
RUNTIME = ROOT / "runtime"
APK_OUT = ROOT / "build" / "app" / "outputs" / "flutter-apk" / "app-release.apk"

DIST = ROOT / "dist"
PC_DIR = DIST / "电脑端"
APP_DIR = PC_DIR / "HashCrack"
APK_DIR = DIST / "手机端"
ZIP_PATH = DIST / "HashCrack-电脑端.zip"

SRC_EXE_NAME = "hashcat_gui.exe"
APP_EXE_NAME = "HashCrack.exe"

# hashcat 跑起来会在自己目录里留一堆临时文件，不能跟着分发出去
HASHCAT_JUNK_SUFFIX = (".restore", ".pid", ".outfiles", ".induct", ".log")
RUNTIME_SKIP_TOP = {"work"}  # 破解临时目录

GUIDE = """HashCrack — hashcat 图形化破解工具
========================================

【怎么用】
1. 双击 HashCrack.exe 启动（无需安装，也不需要装 Python 或 hashcat）
2. 把加密文件拖进窗口，或点「选择文件」
3. 软件自动完成：识别类型 → 提取哈希 → 调用 hashcat 破解 → 显示明文密码
4. 破解成功后会自动尝试修复并解压压缩包，解出的密码可一键复制

【支持的文件】
  ZIP 压缩包          (*.zip)
  PDF 文档            (*.pdf)
  Office 2007+        (*.docx / *.xlsx / *.pptx)
  Office 97-2003      (*.doc / *.xls / *.ppt)
  WiFi 握手包         (*.cap / *.pcap / *.pcapng)
  纯哈希文本文件      (*.txt / *.hash)

【破解成功后的自动解压】
密码破解成功后，软件会对 ZIP / 7z 压缩包自动执行：

  · ZIP：从本地文件头重建中央目录，修复被损坏、被截断、被伪装
    （前面塞了 MP4 头之类）的压缩包，然后解压
  · 7z：直接尝试解压；7z 缺少冗余，若数据块本身损坏则无法修复，
    软件会明确提示「不可修复」而不是假装成功

解压结果放在压缩包同级的 `<压缩包名>_解压/` 目录，重名自动加 (1)。
解压失败不影响已破解出的密码。

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
  runtime\\tools\\7zip\\ 内置 7-Zip（压缩包解压引擎，无需系统安装 7-Zip）
  runtime\\dicts\\       密码字典（可自行增删）

【免责声明】
本工具仅用于恢复自己遗忘的密码、授权的安全测试与教学用途。
请勿用于破解他人文件，否则后果自负。
"""

BAT = '@echo off\r\nrem HashCrack launcher - double click to run\r\nstart "" "%~dp0HashCrack\\HashCrack.exe"\r\n'


def log(msg):
    print(f"[dist] {msg}", flush=True)


def dir_size(path: Path):
    total = 0
    count = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
            count += 1
    return count, total


def backup_old():
    """旧产物挪进 dist/_backup_<时间戳>/，出问题可回滚。

    刻意不重命名 dist/电脑端 本身：只要有一个资源管理器窗口停在
    dist/电脑端/HashCrack，重命名上一级目录就会 WinError 5（拒绝访问），
    而挪动它的子项不受影响。
    """
    import datetime
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak_dir = DIST / f"_backup_{stamp}"
    moved = []
    for src in (PC_DIR / "HashCrack", PC_DIR / "启动 HashCrack.bat", ZIP_PATH):
        if not src.exists():
            continue
        bak_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(bak_dir / src.name))
        moved.append(src.name)
    if moved:
        log(f"旧产物已备份到 dist/{bak_dir.name}/: {', '.join(moved)}")


def run_flutter_build():
    log("编译 Flutter Windows 发布版（可能需要几分钟）...")
    env = os.environ.copy()
    env["PATH"] = str(FLUTTER_BIN) + os.pathsep + env.get("PATH", "")
    env.setdefault("ProgramFiles(x86)", r"C:\Program Files (x86)")
    exe = "flutter.bat" if os.name == "nt" else "flutter"
    r = subprocess.run([str(FLUTTER_BIN / exe), "build", "windows", "--release"],
                       cwd=str(ROOT), env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(r.stdout[-4000:])
        print(r.stderr[-4000:], file=sys.stderr)
        raise SystemExit("Flutter 编译失败")
    log("编译完成")


def copy_build_output():
    """编译产物 → HashCrack/，并把主程序改名为 HashCrack.exe。"""
    if not BUILD_OUT.exists():
        raise SystemExit(f"编译输出不存在: {BUILD_OUT}\n请先编译（去掉 --skip-build）")
    src_exe = BUILD_OUT / SRC_EXE_NAME
    if not src_exe.exists():
        raise SystemExit(f"未找到主程序 {SRC_EXE_NAME}，编译产物异常")

    APP_DIR.mkdir(parents=True, exist_ok=True)
    for item in BUILD_OUT.iterdir():
        if item.name == SRC_EXE_NAME:
            continue
        dst = APP_DIR / item.name
        if item.is_dir():
            shutil.copytree(item, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dst)
    shutil.copy2(src_exe, APP_DIR / APP_EXE_NAME)
    log(f"编译产物已复制，主程序 {SRC_EXE_NAME} → {APP_EXE_NAME}")


def copy_runtime():
    """项目 runtime/ → HashCrack/runtime，剔除 hashcat 运行垃圾。"""
    if not RUNTIME.exists():
        raise SystemExit(f"缺少 runtime 目录: {RUNTIME}")
    dst_root = APP_DIR / "runtime"
    skipped = 0
    for cur, dirs, files in os.walk(RUNTIME):
        cur_p = Path(cur)
        rel = cur_p.relative_to(RUNTIME)
        if rel == Path(".") :
            dirs[:] = [d for d in dirs if d not in RUNTIME_SKIP_TOP]
        (dst_root / rel).mkdir(parents=True, exist_ok=True)
        for f in files:
            if f.lower().endswith(HASHCAT_JUNK_SUFFIX):
                skipped += 1
                continue
            shutil.copy2(cur_p / f, dst_root / rel / f)
    log(f"runtime 已复制（hashcat + Python + 提取工具 + 7-Zip + 字典），"
        f"跳过 {skipped} 个运行临时文件")


def write_pc_extras():
    (APP_DIR / "使用说明.txt").write_text(GUIDE, encoding="utf-8-sig")
    (PC_DIR / "启动 HashCrack.bat").write_text(BAT, encoding="ascii")
    log("已生成 启动 HashCrack.bat 与 使用说明.txt")


def stage_apk():
    dst = APK_DIR / "HashCrack.apk"
    if APK_OUT.exists():
        APK_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(APK_OUT, dst)
        log(f"手机端 APK 已更新（{APK_OUT.stat().st_size / 1024 / 1024:.1f} MB）")
    elif dst.exists():
        log(f"未发现新编译的 APK，保留现有 {dst.name}"
            f"（{dst.stat().st_size / 1024 / 1024:.1f} MB，{_mtime(dst)}）")
    else:
        log("!! 没有 APK：既无编译产物也无历史包，手机端将为空")


def _mtime(p: Path):
    import datetime
    return datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d")


def write_dist_readme(pc_count, pc_size, has_apk):
    apk_line = "  1. 把「手机端\\HashCrack.apk」传到手机并安装" if has_apk else "  （本次打包未包含 APK）"
    text = f"""════════════════════════════════════════
  HashCrack 分发包说明
════════════════════════════════════════

【电脑端】  在 Windows 上使用
  ★ 发给别人请直接发根目录的 HashCrack-电脑端.zip
    对方解压后双击「启动 HashCrack.bat」即可，无需安装。

  1. 打开「电脑端」文件夹
  2. 双击「启动 HashCrack.bat」即可运行
     （也可以直接运行 HashCrack\\HashCrack.exe）
  3. 首次使用请阅读 电脑端\\HashCrack\\使用说明.txt

  ※ 整个「电脑端」文件夹是便携式的：
    拷贝到 U 盘或其它电脑任意位置都能直接运行。

【手机端】  在 Android 手机上使用
{apk_line}
  2. 手机和电脑连同一个局域网
  3. App 内设置 → 填入电脑主界面显示的 IP 和端口 → 测试连接

【体积说明】
  电脑端 {pc_count} 个文件，约 {pc_size / 1024 / 1024:.0f} MB，
  其中大部分是 hashcat 的 600+ 算法模块（支持全部可识别文件类型所必需，无法精简）。

【本包内含】
  · 压缩包破解成功后的自动修复 + 解压（ZIP 重建中央目录 / 7z 尽力解压）
  · 内置 7-Zip，无需系统另装
"""
    (DIST / "说明.txt").write_text(text, encoding="utf-8-sig")
    log("已生成 dist/说明.txt")


def verify():
    checks = [
        ("主程序", APP_DIR / APP_EXE_NAME),
        ("Flutter 运行库", APP_DIR / "flutter_windows.dll"),
        ("应用资源 data/", APP_DIR / "data"),
        ("启动脚本", PC_DIR / "启动 HashCrack.bat"),
        ("使用说明", APP_DIR / "使用说明.txt"),
        ("hashcat 内核", APP_DIR / "runtime" / "hashcat" / "hashcat.exe"),
        ("Python 运行时", APP_DIR / "runtime" / "python" / "python.exe"),
        ("ZIP 提取器", APP_DIR / "runtime" / "tools" / "zip2john.py"),
        ("7-Zip 引擎", APP_DIR / "runtime" / "tools" / "7zip" / "7z.exe"),
        ("7-Zip 库", APP_DIR / "runtime" / "tools" / "7zip" / "7z.dll"),
        ("WiFi 工具", APP_DIR / "runtime" / "tools" / "hcxtools" / "hcxpcapngtool.exe"),
        ("内置字典", APP_DIR / "runtime" / "dicts" / "common.txt"),
    ]
    ok = True
    print("  校验分发包完整性:")
    for label, p in checks:
        exists = p.exists()
        ok = ok and exists
        print(f"    [{'OK ' if exists else '缺失'}] {label}")
    if not ok:
        raise SystemExit("分发包不完整，已中止")
    # hashcat 垃圾文件不该出现在包里
    junk = [f for f in (APP_DIR / "runtime" / "hashcat").iterdir()
            if f.is_file() and f.name.lower().endswith(HASHCAT_JUNK_SUFFIX)]
    if junk:
        print(f"    !! 仍有 {len(junk)} 个 hashcat 临时文件")
    return ok


def make_zip():
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()
    log("正在压缩 电脑端 → HashCrack-电脑端.zip（文件多，请耐心等待）...")
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for f in sorted(PC_DIR.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(PC_DIR))
    log(f"压缩完成: {ZIP_PATH.name}  ({ZIP_PATH.stat().st_size / 1024 / 1024:.1f} MB)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true", help="跳过编译，用现有产物打包")
    ap.add_argument("--skip-zip", action="store_true", help="不压缩分发包")
    args = ap.parse_args()

    if not args.skip_build:
        run_flutter_build()

    backup_old()

    APP_DIR.mkdir(parents=True, exist_ok=True)

    copy_build_output()
    copy_runtime()
    write_pc_extras()
    stage_apk()
    verify()

    pc_count, pc_size = dir_size(PC_DIR)
    write_dist_readme(pc_count, pc_size, (APK_DIR / "HashCrack.apk").exists())
    log(f"电脑端 {pc_count} 个文件，{pc_size / 1024 / 1024:.0f} MB")

    if not args.skip_zip:
        make_zip()

    log("全部完成")


if __name__ == "__main__":
    main()