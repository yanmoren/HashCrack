#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复 Windows 构建所需的插件链接。

背景
----
Flutter 构建 Windows 应用时，会为平台插件在
`windows\\flutter\\ephemeral\\.plugin_symlinks\\<插件名>` 创建符号链接。

但在未开启「开发者模式」的 Windows 上，创建符号链接会因权限不足失败：
  - Dart 的 Link.createSync 先报 errno 1314（权限不足）
  - Flutter 会回退到 `mklink /J` 创建 NTFS junction
  - 若 junction 也没建成，Flutter 会残留一个**空目录**，
    下次构建时 createSync 又报 errno 183（文件已存在），构建直接卡死

本脚本直接用 `mklink /J` 建 NTFS junction（不需要管理员权限），
让 Flutter 的 `if (link.existsSync()) continue;` 判定命中并跳过，
从而彻底绕开这个坑。

用法
----
    python scripts/fix_plugin_links.py [项目根目录]
"""

import json
import subprocess
import sys
from pathlib import Path


def fix(project_root: Path) -> bool:
    deps_file = project_root / ".flutter-plugins-dependencies"
    if not deps_file.exists():
        print(f"  未找到 {deps_file}，跳过（pub get 后会自动生成）")
        return False

    deps = json.loads(deps_file.read_text(encoding="utf-8"))
    plugins = deps.get("plugins", {}).get("windows", [])
    if not plugins:
        print("  没有需要链接的 Windows 插件")
        return True

    link_root = project_root / "windows" / "flutter" / "ephemeral" / ".plugin_symlinks"
    link_root.mkdir(parents=True, exist_ok=True)

    all_ok = True
    for p in plugins:
        name = p["name"]
        src = Path(p["path"].rstrip("\\/"))
        dst = link_root / name

        if not src.exists():
            print(f"  [跳过] {name}: 源目录不存在 {src}")
            all_ok = False
            continue

        # 目标已是有效链接或非空目录 → 认为就绪
        if dst.exists() and any(dst.iterdir()):
            print(f"  [就绪] {name}")
            continue

        # 清掉残留的空目录 / 坏链接（用 rmdir，避免误删 junction 指向的真实内容）
        if dst.exists() or dst.is_symlink():
            subprocess.run(["cmd", "/c", "rmdir", str(dst)],
                           capture_output=True)

        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(dst), str(src)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            print(f"  [已建] {name} -> {src.name}")
        else:
            detail = (r.stdout or "").strip() or (r.stderr or "").strip()
            print(f"  [失败] {name}: {detail}")
            all_ok = False

    # 校验
    print("  --- 校验 ---")
    for p in plugins:
        d = link_root / p["name"]
        ok = d.exists() and any(d.iterdir())
        if not ok:
            all_ok = False
        print(f"  [{'OK ' if ok else '缺失'}] {p['name']}")

    return all_ok


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    print(f"修复插件链接: {root}")
    sys.exit(0 if fix(root) else 1)
