import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models/archive_report.dart';
import '../models/file_type.dart';
import 'app_paths.dart';

/// 解压执行器：调用内置 7-Zip 把压缩包解开。
///
/// 职责边界：**只管调用外部工具并翻译结果**。结构修复由
/// [ZipRepairService] 负责，本文件不碰字节解析。
///
/// 为什么用内置的 7-Zip 而不是纯 Dart 库：解压这件事上正确性压倒一切。
/// 用户拿到密码后最怕的是"密码明明对、文件却解不开"，这种事出一次
/// 整个软件的信任就没了。7-Zip 是这一领域最成熟的实现，ZIP（ZipCrypto /
/// WinZip AES）、7z（含加密头部）、ZIP64、solid 压缩、GBK 文件名它都处理过。
class ArchiveExtractService {
  /// 是否支持解压该类型。只有 zip / 7z 参与，其余（PDF、Office…）跳过。
  static bool supports(DetectedFileType type) =>
      type == DetectedFileType.zip || type == DetectedFileType.sevenZip;

  /// 解压空间预检的冗余系数：目录项、文件系统块对齐都会让实际占用
  /// 略大于内容之和，留 20% 余量避免"解到 99% 磁盘满"。
  static const double _spaceFactor = 1.2;

  static const Duration _listTimeout = Duration(seconds: 30);

  Future<ArchiveReport> extract({
    required String archivePath,
    required String password,
    required DetectedFileType type,
    void Function(double progress)? onProgress,
    bool Function()? isCancelled,
  }) async {
    final report = ArchiveReport(status: ExtractStatus.running);

    if (!supports(type)) {
      report.status = ExtractStatus.skipped;
      report.errorSummary = '该文件类型不参与自动解压';
      return report;
    }

    final exe = AppPaths.sevenZipExe;
    if (exe.isEmpty) {
      report.status = ExtractStatus.failed;
      report.errorSummary = '未找到内置解压引擎（runtime/tools/7zip/7z.exe）。'
          '请使用最新版安装包，或在设置中指定 7z.exe 路径。';
      return report;
    }

    final archive = File(archivePath);
    if (!await archive.exists()) {
      report.status = ExtractStatus.failed;
      report.errorSummary = '压缩包不存在或已被移动';
      return report;
    }

    // 输出目录：与压缩包同级，重名自动加序号，绝不覆盖已有目录
    final outDir = await _allocateOutputDir(archivePath);
    report.outputDir = outDir;

    // 空间预检：宁可"还没开始就告诉你磁盘不够"，也不要解到一半写满分区。
    // 解压后的大小拿不准时（加密头无法读取）跳过预检，不阻断主流程。
    final needed = await _estimateUncompressedBytes(exe, archivePath, password);
    if (needed != null) {
      final free = await _freeSpaceAt(archivePath);
      if (free != null && free < (needed * _spaceFactor).round()) {
        report.status = ExtractStatus.failed;
        report.errorSummary =
            '磁盘空间不足：需要约 ${_mb(needed * _spaceFactor)}，'
            '当前可用 ${_mb(free.toDouble())}，还差 ${_mb(needed * _spaceFactor - free)}';
        return report;
      }
    }

    final args = <String>[
      'x',
      '-p$password',
      '-o$outDir',
      '-y',
      '-bso0', // 屏蔽标准输出噪音，进度走 -bb1 的标准错误
      '-bsp1',
      '-bb1',
      // ZIP 里未声明 UTF-8 的文件名按系统代码页（简体中文 = 936）解读。
      // 判定依据是标志位而不是"先解一次看有没有乱码"——乱码无法可靠识别。
      if (type == DetectedFileType.zip && await _zipNeedsLegacyCodePage(archivePath))
        '-mcp=936',
      archivePath,
    ];

    final run = await _run(exe, args, onProgress: onProgress, isCancelled: isCancelled);

    if (run.cancelled) {
      report.status = ExtractStatus.failed;
      report.errorSummary = '解压已取消';
      await _collectFiles(outDir, report);
      return report;
    }

    // 密码错误时必须整目录丢弃。7-Zip 在密码不对时**仍然会在磁盘上留下
    // 0 字节的"壳文件"**，如果照实收集就会报告成"部分解出"——
    // 用户会以为拿到了数据，实际是空的。这比直接报错有害得多。
    if (_looksLikeWrongPassword(run.output)) {
      await _discard(outDir);
      report.status = ExtractStatus.failed;
      report.files.clear();
      report.errorSummary = '密码错误，无法解开该压缩包';
      return report;
    }

    await _collectFiles(
      outDir,
      report,
      failedNames: run.errors.map((e) => e.name).where((n) => n.isNotEmpty).toSet(),
    );

    final canOpen = !_looksLikeNotAnArchive(run.output);
    if (report.files.isEmpty) {
      report.status = ExtractStatus.failed;
      report.errorSummary = _explainFailure(type, run, canOpen);
      return report;
    }

    if (run.errors.isNotEmpty || run.exitCode != 0) {
      report.status = ExtractStatus.partial;
      report.failed.addAll(run.errors);
      if (run.errors.isEmpty) {
        // 退出码非 0 却没抓到逐条错误。此时报"救出 N 个、0 个失败"最让人
        // 困惑——用户看着一个"部分成功"却说不出哪里不好。把 7-Zip 的原话
        // 附上，让结论可追溯。
        report.errorSummary = '解压完成但有警告（退出码 ${run.exitCode}）：${_tail(run.output)}';
      } else {
        report.errorSummary = '救出 ${report.files.length} 个文件，${run.errors.length} 个失败';
      }
    } else {
      report.status = ExtractStatus.success;
      report.progress = 1.0;
    }
    return report;
  }

  // ───────────────────────── 失败原因翻译 ─────────────────────────

  /// 把 7-Zip 的输出翻译成用户能理解、且**不撒谎**的结论。
  ///
  /// 设计约束（见设计文档 3.2）：7z 头部损坏时必须明说"救不出来"，
  /// 不能用"已解压 0 个文件"这种模糊措辞掩盖失败。
  String _explainFailure(DetectedFileType type, _RunResult run, bool canOpen) {
    final lower = run.output.toLowerCase();

    if (lower.contains('wrong password') ||
        lower.contains('password is not correct') ||
        lower.contains('cannot open encrypted')) {
      return '密码错误，无法解开该压缩包';
    }
    if (lower.contains('crc failed') || lower.contains('data error')) {
      return '压缩包内数据已损坏（CRC 校验失败），未能解出文件';
    }
    if (!canOpen) {
      if (type == DetectedFileType.sevenZip) {
        // 7z 没有冗余、结构集中在文件末尾，头部一坏就真的救不回来。
        // 这是格式的固有性质，如实告知比给一个假希望有用。
        return '7z 无冗余，头部损坏无法抢救（能解出的部分为 0 个文件）';
      }
      return '压缩包结构损坏，无法读取目录，未能解出任何文件';
    }
    final first = run.errors.isNotEmpty ? run.errors.first.reason : '';
    return first.isEmpty ? '解压失败（退出码 ${run.exitCode}）' : '解压失败：$first';
  }

  bool _looksLikeNotAnArchive(String output) {
    final lower = output.toLowerCase();
    return lower.contains('is not archive') ||
        lower.contains('cannot open the file as archive') ||
        lower.contains('unexpected end of archive');
  }

  // ───────────────────────── 目录与空间 ─────────────────────────

  /// 分配输出目录 `<包名>_解压`，已存在则依次尝试 `(1)`、`(2)`。
  Future<String> _allocateOutputDir(String archivePath) async {
    final sep = Platform.pathSeparator;
    final fileName = archivePath.split(RegExp(r'[/\\]')).last;
    final dot = fileName.lastIndexOf('.');
    final base = dot > 0 ? fileName.substring(0, dot) : fileName;
    final parent = File(archivePath).parent.path;

    var candidate = '$parent$sep${base}_解压';
    var n = 0;
    while (await Directory(candidate).exists()) {
      n++;
      candidate = '$parent$sep${base}_解压($n)';
    }
    return candidate;
  }

  /// 往上层目录找可用空间（输出目录还不存在，只能问它的父目录）。
  Future<int?> _freeSpaceAt(String archivePath) async {
    try {
      final parent = File(archivePath).parent;
      // Dart 没有跨平台的可用空间 API，用系统命令问到不了就放弃预检
      if (Platform.isWindows) {
        final drive = parent.absolute.path.split(':').first;
        final r = await Process.run(
          'wmic',
          ['logicaldisk', 'where', "DeviceID='$drive:'", 'get', 'FreeSpace'],
        ).timeout(const Duration(seconds: 10));
        final digits = RegExp(r'\d{6,}')
            .allMatches(r.stdout.toString())
            .map((m) => int.tryParse(m.group(0)!) ?? 0)
            .toList();
        if (digits.isNotEmpty) return digits.reduce((a, b) => a > b ? a : b);
      }
      return null;
    } catch (_) {
      return null; // 预检失败不阻断解压
    }
  }

  /// 用 `7z l -slt` 估算解压后总大小。拿不到就返回 null（跳过预检）。
  Future<int?> _estimateUncompressedBytes(
    String exe,
    String archivePath,
    String password,
  ) async {
    try {
      final r = await Process.run(
        exe,
        ['l', '-slt', '-p$password', archivePath],
      ).timeout(_listTimeout);
      if (r.exitCode != 0 && r.exitCode != 1) return null;

      var total = 0;
      var found = false;
      for (final line in const LineSplitter().convert(r.stdout.toString())) {
        // -slt 的每条记录里 `Size = ` 是原始大小，`Packed Size = ` 才是压缩后。
        // 必须先判 Packed，否则会把压缩后大小也算进来。
        if (line.startsWith('Packed Size = ')) continue;
        if (line.startsWith('Size = ')) {
          final v = int.tryParse(line.substring(7).trim());
          if (v != null) {
            total += v;
            found = true;
          }
        }
      }
      return found ? total : null;
    } catch (_) {
      return null;
    }
  }

  /// ZIP 条目名是否需要用旧代码页（GBK）解读。
  ///
  /// 判定依据是**标志位**：条目未置 UTF-8 位（bit 11）且名字里出现非 ASCII 字节。
  static Future<bool> _zipNeedsLegacyCodePage(String archivePath) async {
    try {
      final raf = await File(archivePath).open();
      try {
        final total = await raf.length();
        // 只扫中央目录：从尾部找 EOCD，再按记录逐条看名字
        final searchLen = total < (22 + 65535) ? total : (22 + 65535);
        await raf.setPosition(total - searchLen);
        final tail = await raf.read(searchLen);
        var eocd = -1;
        for (var i = tail.length - 22; i >= 0; i--) {
          if (tail[i] == 0x50 &&
              tail[i + 1] == 0x4b &&
              tail[i + 2] == 0x05 &&
              tail[i + 3] == 0x06) {
            eocd = i;
            break;
          }
        }
        if (eocd < 0 || eocd + 22 > tail.length) return false;

        final count = tail[eocd + 10] | (tail[eocd + 11] << 8);
        final cdOffset = tail[eocd + 16] |
            (tail[eocd + 17] << 8) |
            (tail[eocd + 18] << 16) |
            (tail[eocd + 19] << 24);
        if (count <= 0 || count == 0xFFFF) return false;

        await raf.setPosition(cdOffset);
        for (var i = 0; i < count; i++) {
          final head = await raf.read(46);
          if (head.length < 46) return false;
          if (!(head[0] == 0x50 && head[1] == 0x4b && head[2] == 0x01 && head[3] == 0x02)) {
            return false;
          }
          final flags = head[8] | (head[9] << 8);
          final nameLen = head[28] | (head[29] << 8);
          final extraLen = head[30] | (head[31] << 8);
          final commentLen = head[32] | (head[33] << 8);
          final name = await raf.read(nameLen);
          final utf8Flag = (flags & 0x800) != 0;
          if (!utf8Flag && name.any((b) => b >= 0x80)) return true;
          await raf.setPosition(
            await raf.position() + extraLen + commentLen,
          );
        }
        return false;
      } finally {
        await raf.close();
      }
    } catch (_) {
      return false;
    }
  }

  /// 解压完成后按实际磁盘内容收集文件清单。
  ///
  /// 以磁盘为准而不是以 7-Zip 的输出为准：输出解析会漏掉
  /// "报了 CRC 错但文件其实写出来了"这类情况，而用户关心的是磁盘上有什么。
  ///
  /// 例外：[failedNames] 里那些 0 字节的文件是 7-Zip 留下的"壳",
  /// 不代表任何可用内容，必须排除——否则"部分解出"会变成假结论。
  Future<void> _collectFiles(
    String outDir,
    ArchiveReport report, {
    Set<String>? failedNames,
  }) async {
    final dir = Directory(outDir);
    if (!await dir.exists()) return;
    final base = dir.absolute.path;
    await for (final entity in dir.list(recursive: true, followLinks: false)) {
      if (entity is! File) continue;
      final rel = entity.path
          .substring(base.length)
          .replaceAll(RegExp(r'^[/\\]+'), '')
          .replaceAll('\\', '/');
      final size = await entity.length();
      if (size == 0 && (failedNames?.contains(rel) ?? false)) continue;
      report.files.add(ExtractedFile(relativePath: rel, size: size));
    }
    report.files.sort((a, b) => a.relativePath.compareTo(b.relativePath));
  }

  /// 7-Zip 是否明确报了密码错误
  bool _looksLikeWrongPassword(String output) {
    final lower = output.toLowerCase();
    return lower.contains('wrong password') ||
        lower.contains('password is not correct') ||
        lower.contains('cannot open encrypted');
  }

  /// 丢弃整个输出目录（密码错误、或被中止时用）
  Future<void> _discard(String dir) async {
    try {
      final d = Directory(dir);
      if (await d.exists()) await d.delete(recursive: true);
    } catch (_) {
      // 清理失败不影响结论：报告依然是"失败"，只是可能留下空目录
    }
  }

  // ───────────────────────── 进程执行 ─────────────────────────

  Future<_RunResult> _run(
    String exe,
    List<String> args, {
    void Function(double)? onProgress,
    bool Function()? isCancelled,
  }) async {
    final proc = await Process.start(exe, args);
    final buffer = StringBuffer();
    final errors = <FailedEntry>[];
    var cancelled = false;

    final stdoutDone = proc.stdout
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen((s) {
      buffer.write(s);
      _harvestErrors(s, errors);
    }).asFuture<void>();

    final stderrDone = proc.stderr
        .transform(const Utf8Decoder(allowMalformed: true))
        .listen((s) {
      buffer.write(s);
      _harvestErrors(s, errors);
      final pct = _parseProgress(s);
      if (pct != null) onProgress?.call(pct);
    }).asFuture<void>();

    // 取消检测：轮询而不是监听事件，避免依赖平台信号
    Timer? watch;
    if (isCancelled != null) {
      watch = Timer.periodic(const Duration(milliseconds: 300), (_) {
        if (isCancelled()) {
          cancelled = true;
          proc.kill();
        }
      });
    }

    final code = await proc.exitCode;
    watch?.cancel();
    await stdoutDone;
    await stderrDone;
    onProgress?.call(1.0);

    return _RunResult(
      exitCode: cancelled ? -1 : code,
      output: buffer.toString(),
      errors: _dedupe(errors),
      cancelled: cancelled,
    );
  }

  /// 从 7-Zip 的 `-bb1` 输出里抽取百分比
  double? _parseProgress(String chunk) {
    final m = RegExp(r'(\d{1,3})%').firstMatch(chunk);
    if (m == null) return null;
    final v = int.tryParse(m.group(1)!);
    return v == null ? null : (v / 100).clamp(0.0, 1.0);
  }

  /// 收集逐条失败信息。
  ///
  /// 7-Zip 的报错形态是 `ERROR: <原因> : <路径>` 或紧邻的几行，
  /// 这里只提取能确认的"原因 + 条目名"，提取不到就跳过，
  /// 不臆造条目名——编出来的条目名比没有更误导。
  void _harvestErrors(String chunk, List<FailedEntry> out) {
    for (final raw in const LineSplitter().convert(chunk)) {
      final line = raw.trim();
      if (line.isEmpty) continue;
      if (line.startsWith('ERROR:')) {
        final body = line.substring(6).trim();
        final parts = body.split(' : ');
        if (parts.length >= 2) {
          out.add(FailedEntry(name: parts.last.trim(), reason: parts.first.trim()));
        } else {
          out.add(FailedEntry(name: '', reason: body));
        }
      } else if (line.contains('CRC Failed') || line.contains('Data Error')) {
        out.add(FailedEntry(name: '', reason: 'CRC 校验失败'));
      }
    }
  }

  List<FailedEntry> _dedupe(List<FailedEntry> items) {
    final seen = <String>{};
    final out = <FailedEntry>[];
    for (final e in items) {
      final key = '${e.name}|${e.reason}';
      if (seen.add(key)) out.add(e);
    }
    return out;
  }

  String _mb(double bytes) => '${(bytes / 1024 / 1024).toStringAsFixed(1)} MB';

  /// 取外部工具输出的最后几行，用于把原话带给用户。
  /// 截断而不是全文照搬：输出可能几百行，塞进界面反而没人看。
  String _tail(String output) {
    final lines = const LineSplitter()
        .convert(output)
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty)
        .toList();
    if (lines.isEmpty) return '（无输出）';
    final tail = lines.length <= 3 ? lines : lines.sublist(lines.length - 3);
    var s = tail.join(' / ');
    if (s.length > 300) s = '${s.substring(0, 300)}…';
    return s;
  }
}

class _RunResult {
  final int exitCode;
  final String output;
  final List<FailedEntry> errors;
  final bool cancelled;
  _RunResult({
    required this.exitCode,
    required this.output,
    required this.errors,
    required this.cancelled,
  });
}
