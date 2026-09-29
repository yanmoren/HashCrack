# 压缩包修复与自动解压 — 实施计划

**Goal:** 让 HashCrack 在破解成功后自动用密码解开 ZIP/7z 压缩包，并在 ZIP 结构损坏时先重建中央目录再解压。

**Architecture:** 三个新增模块各司其职——`ZipRepairService` 纯 Dart 做 ZIP 结构修复（不解压不解密）、`ArchiveExtractService` 调用内置 `7z.exe` 做解压、`ArchiveReport` 承载结果。解压阶段挂在 `TaskOrchestrator` 破解成功之后，**异常完全隔离**，不影响"已破解"状态。

**Tech Stack:** Flutter 3.47.3 / Dart 3.13；`dart:io`（`RandomAccessFile` 流式读写、`RawZLibFilter` 增量 inflate）；内置 7-Zip 26.03 命令行；无新增 pub 依赖。

**Spec:** `docs/superpowers/specs/2026-09-29-zip-7z-repair-extract-design.md`

---

## 文件结构

| 文件 | 职责 |
|---|---|
| `lib/models/archive_report.dart`（新） | 结果模型：`ExtractStatus` / `ExtractedFile` / `FailedEntry` / `RepairReport` / `ArchiveReport`，含 `toJson`/`fromJson` |
| `lib/services/zip_repair_service.dart`（新） | ZIP 结构修复：EOCD 探测 → 本地头扫描 → 条目重建 → 流式写出 |
| `lib/services/archive_extract_service.dart`（新） | 解压执行器：调 `7z.exe`、中文名编码、空间预检、输出解析 |
| `lib/services/app_paths.dart`（改） | 新增 `sevenZipDir` / `sevenZipExe` |
| `lib/models/task.dart`（改） | 新增 `ArchiveReport? extractReport` 并参与序列化 |
| `lib/services/task_orchestrator.dart`（改） | 破解成功后新增解压阶段 |
| `lib/screens/result_screen.dart`（改） | 解压结果区块 |
| `lib/screens/settings_screen.dart`（改） | 大包阈值设置；自检增加 7-Zip 版本 |
| `lib/services/server_service.dart`（改） | `GET /api/task/<id>/extract/download`（支持 Range） |
| `lib/services/remote_client.dart`（改） | 手机端下载解压结果 |
| `scripts/build_portable.py`（改） | 四级来源获取并组装 `runtime/tools/7zip/` |
| `README.md` / `dist/电脑端/HashCrack/使用说明.txt`（改） | 功能说明与第三方许可声明 |

## 接口约定（后续任务必须与此一致）

```dart
// lib/models/archive_report.dart
enum ExtractStatus { pending, running, success, partial, failed, skipped }

class ExtractedFile { final String relativePath; final int size; }

class FailedEntry { final String name; final String reason; }

class RepairReport {
  final bool attempted;        // 是否走了修复链路
  final bool succeeded;
  final String? repairedPath;  // 修复产物路径（受阈值控制，可能为 null）
  final int recoveredEntries;
  final List<FailedEntry> droppedEntries;
  final String? error;
}

class ArchiveReport {
  ExtractStatus status;
  String outputDir;
  List<ExtractedFile> files;
  List<FailedEntry> failed;
  RepairReport? repair;
  String? errorSummary;
  double progress;
}
```

```dart
// lib/services/zip_repair_service.dart
class ZipRepairService {
  /// 扫描并重建中央目录。sourcePath 只读，产物写到 outputPath。
  static Future<RepairReport> repair(
    String sourcePath, {
    required String outputPath,
    void Function(double progress)? onProgress,
  });
}

// lib/services/archive_extract_service.dart
class ArchiveExtractService {
  Future<ArchiveReport> extract({
    required String archivePath,
    required String password,
    required DetectedFileType type,
    void Function(double progress)? onProgress,
    bool Function()? isCancelled,
  });
}
```

---

### Task 1: 内置 7-Zip 二进制

**Files:**
- Create: `runtime/tools/7zip/7z.exe`, `runtime/tools/7zip/7z.dll`, `runtime/tools/7zip/License.txt`
- Test: 手工验证 `runtime/tools/7zip/7z.exe` 能自报版本

- [ ] 从 `C:\Program Files\7-Zip\` 复制 `7z.exe`、`7z.dll`、`License.txt` 到 `runtime/tools/7zip/`
- [ ] 验证：运行 `runtime\tools\7zip\7z.exe` ，预期首行含 `7-Zip 26.03`
- [ ] 验证解压能力：用它对一个已知 zip 执行 `x -y -o<临时目录>`，确认退出码 0 且文件解出

### Task 2: Job 对象驱动的可取消进程包装（复用既有模式）

**Files:**
- Test: `test/process_runner_test.dart`（新）

- [ ] 写失败测试：`runProcess` 能捕获 stdout/stderr 全部行、返回退出码、`isCancelled` 返回 true 时终止子进程
- [ ] 运行测试确认失败
- [ ] 在 `lib/services/archive_extract_service.dart` 内实现私有 `_run7z`（先满足测试所需的最小接口）
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 可取消的外部进程执行包装`

### Task 3: 结果模型 `archive_report.dart`

**Files:**
- Create: `lib/models/archive_report.dart`
- Test: `test/archive_report_test.dart`（新）

- [ ] 写失败测试：`ArchiveReport.toJson` → `fromJson` 往返后所有字段相等；`repair` 为 null 时序列化不报错；`failed` 空列表往返正确
- [ ] 运行测试确认失败
- [ ] 实现模型与序列化
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 解压结果模型`

### Task 4: ZIP 修复器 — 基础解析（TDD）

**Files:**
- Create: `lib/services/zip_repair_service.dart`
- Test: `test/zip_repair_test.dart`（新）
- 测试样本生成：`scripts/make_zip_samples.py`（新，用 Bandizip 生成真 ZipCrypto 样本，用 7z.exe 生成 AES 样本）

- [ ] 写失败测试（正常包）：完整 zip 走 `repair()` 后 `attempted == false`、`recoveredEntries == 条目数`、产物被逐字节校验可被 7-Zip 正常打开
- [ ] 运行测试确认失败
- [ ] 实现 EOCD 定位（从末尾向前最多 65557 字节）与中央目录解析
- [ ] 运行测试确认通过
- [ ] 提交：`feat: ZIP 修复器 - EOCD 与中央目录解析`

### Task 5: ZIP 修复器 — 本地头扫描与重建

**Files:**
- Modify: `lib/services/zip_repair_service.dart`
- Test: `test/zip_repair_test.dart`

- [ ] 写失败测试：① 中央目录被整体删除（只留本地头）→ 修复后条目数与内容一致；② EOCD 被截断 → 修复成功；③ 数据区内含 `PK\x03\x04` 字面量 → 不得被误判为条目
- [ ] 运行测试确认失败
- [ ] 实现 `pk\x03\x04` 扫描、头解析、误命中过滤（压缩方法白名单 0/8/9/12/14/93/95/98/99、长度越界、非法控制字符）
- [ ] 运行测试确认通过
- [ ] 提交：`feat: ZIP 修复器 - 本地头扫描重建`

### Task 6: ZIP 修复器 — 加密条目、ZIP64、数据描述符

**Files:**
- Modify: `lib/services/zip_repair_service.dart`
- Test: `test/zip_repair_test.dart`

- [ ] 写失败测试：① 加密条目的密文段在修复前后**逐字节一致**；② ZIP64 条目（>4GB 或条目数 >65535 之一，用构造样本）修复后可打开；③ data descriptor 条目（bit 3）：精确法（未加密 deflate 用 `RawZLibFilter` 增量解码定界）与启发式回退各一例
- [ ] 运行测试确认失败
- [ ] 实现 ZIP64 扩展字段解析、ZIP64 记录写入、data descriptor 定界（精确法优先、启发式带严格校验）
- [ ] 流式写出：1 MB 缓冲区按 `offset + length` 复制，**禁止整包读入内存**
- [ ] 运行测试确认通过
- [ ] 提交：`feat: ZIP 修复器 - 加密/ZIP64/数据描述符`

### Task 7: 解压执行器

**Files:**
- Create: `lib/services/archive_extract_service.dart`（补齐）
- Modify: `lib/services/app_paths.dart`（新增 `sevenZipDir` / `sevenZipExe`）
- Test: `test/archive_extract_test.dart`（新）

- [ ] 写失败测试：① 用 `7z.exe` 解开已知密码的 ZipCrypto 样本 → `status == success` 且文件内容一致；② 错密码 → `status == failed` 且 `errorSummary` 含密码错误；③ 空间不足（把输出指到极小可用空间）→ 中止且不产生输出目录
- [ ] 运行测试确认失败
- [ ] 实现 `extract()`：命令 `x -p<pw> -o<dir> -y -bso0 -bsp1 -bb1`；解析 `-bb1` 进度；空间预检 `原始大小和 × 1.2`；名字未置 UTF-8 标志位（bit 11）时追加 `-mcp=936`
- [ ] 实现输出目录命名 `<包名>_解压` 与重名 `(1)(2)`
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 解压执行器（7-Zip 内置引擎）`

### Task 8: 流水线接入

**Files:**
- Modify: `lib/models/task.dart`、`lib/services/task_orchestrator.dart`
- Test: `test/extract_pipeline_test.dart`（新）

- [ ] 写失败测试：① 破解成功且是 zip → `task.extractReport.status == success` 且 `task.status == cracked`；② 解压阶段抛异常 → `task.status` 仍为 `cracked`，`extractReport.errorSummary` 非空；③ 类型为 pdf 等不可解压类型 → `status == skipped`
- [ ] 运行测试确认失败
- [ ] `task.dart` 加 `ArchiveReport? extractReport` 并接入序列化
- [ ] `task_orchestrator.dart` 在 `_performCracking` 返回 true 后调用 `_extractArchive(task)`，内部整体 try/catch
- [ ] ZIP 解压失败时自动调用 `ZipRepairService.repair()`，产物受大包阈值控制（默认 2048 MB），再用产物重试解压
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 破解成功后自动解压接入流水线`

### Task 9: 结果页 UI

**Files:**
- Modify: `lib/screens/result_screen.dart`
- Test: `test/result_extract_section_test.dart`（新）

- [ ] 写失败测试：① success 渲染文件清单与"打开文件夹"；② failed 渲染原因文案；③ 7z 头部损坏场景渲染"7z 无冗余，头部损坏无法抢救"而非"已解压 0 个文件"
- [ ] 运行测试确认失败
- [ ] 实现解压区块（状态、清单、打开文件夹、下载入口）
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 结果页解压结果区块`

### Task 10: 设置与自检

**Files:**
- Modify: `lib/screens/settings_screen.dart`
- Test: `test/settings_extract_test.dart`（新）

- [ ] 写失败测试：大包阈值默认 2048 且可改并持久化；自检项展示 7-Zip 版本，缺失时展示指引文案
- [ ] 运行测试确认失败
- [ ] 实现设置项与自检项
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 大包阈值设置与 7-Zip 自检`

### Task 11: 手机端下载接口

**Files:**
- Modify: `lib/services/server_service.dart`、`lib/services/remote_client.dart`
- Test: `test/extract_download_test.dart`（新）

- [ ] 写失败测试：① 不带 `file` 参数返回整目录 zip 且 `Content-Disposition` 文件名正确；② `Range: bytes=100-199` 返回 206 与正确切片；③ 任务不存在或目录已删 → 明确错误码而非空白
- [ ] 运行测试确认失败
- [ ] 实现路由与流式打包、Range 支持、RFC 5987 文件名编码
- [ ] 运行测试确认通过
- [ ] 提交：`feat: 手机端下载解压结果（支持断点续传）`

### Task 12: 打包脚本与文档

**Files:**
- Modify: `scripts/build_portable.py`、`README.md`、`dist/电脑端/HashCrack/使用说明.txt`

- [ ] 在 `build_portable.py` 实现四级来源获取（项目内 `tools/7zip/` → 本机安装 → `PATH` → 官方源下载 + SHA-256 校验），全部失败则 `sys.exit(1)`
- [ ] 组装 `runtime/tools/7zip/`，打印版本号与来源序号
- [ ] 运行构建，确认产物内含 `runtime/tools/7zip/7z.exe` 且程序自检可识别
- [ ] 更新 README 功能说明与第三方组件许可（7-Zip LGPL）
- [ ] 提交：`build: 内置 7-Zip 并补充许可声明`

### Task 13: 端到端回归

**Files:**
- Test: `test/archive_e2e_test.dart`（新，慢测，单独标记）

- [ ] 自造 ZipCrypto / WinZip AES / 7z AES（含加密头）三个加密样本 → 破解 → 自动解压 → **逐字节校验解出文件与原文件一致**
- [ ] 截断中央目录的 zip → 修复 → 解压 → 内容一致
- [ ] GBK 中文名 zip → 解压后文件名正确无乱码
- [ ] 提交：`test: 压缩包修复与解压端到端回归`

---

## 完成判据

- 13 个任务全部通过，`flutter test` 全绿
- 真实加密样本端到端跑通，解出文件与原文件逐字节一致
- 构建产物含 `runtime/tools/7zip/`，程序内"运行环境自检"能报出 7-Zip 版本
- 解压失败时任务仍显示"已破解"（`cracked`）
