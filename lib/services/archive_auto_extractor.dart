import 'dart:io';

import '../models/archive_report.dart';
import '../models/file_type.dart';
import 'archive_extract_service.dart';
import 'zip_repair_service.dart';

/// 破解成功后的自动解压编排。
///
/// 单独的组件而不是塞进 [TaskOrchestrator]：这段逻辑有完整的决策链
/// （直接解 → 失败则修 → 用修复产物重试 → 按阈值决定留不留修复包），
/// 而且**完全不依赖 hashcat**，可以独立测试。塞进编排器就只能靠真实破解
/// 才能触发，测试成本会高到没人愿意写。
class ArchiveAutoExtractor {
  final ArchiveExtractService extractService;

  /// 超过这个大小的包不留修复产物（默认 2 GB）。
  ///
  /// 修复要为原包写一份完整拷贝。小包留一份"修好的包"很值——用户下次
  /// 不用再修；大包留档等于凭空吃掉一倍磁盘，所以只解压不保留。
  final int repairedZipSizeLimitBytes;

  static const int defaultRepairedZipSizeLimit = 2 * 1024 * 1024 * 1024;

  ArchiveAutoExtractor({
    ArchiveExtractService? extractService,
    this.repairedZipSizeLimitBytes = defaultRepairedZipSizeLimit,
  }) : extractService = extractService ?? ArchiveExtractService();

  static bool supports(DetectedFileType type) => ArchiveExtractService.supports(type);

  /// 执行自动解压。**本方法不抛异常**——解压是附加产出，
  /// 任何意外都必须落成一份报告，不能影响任务的"已破解"状态。
  Future<ArchiveReport> run({
    required String archivePath,
    required String password,
    required DetectedFileType type,
    void Function(ArchiveReport)? onUpdate,
    bool Function()? isCancelled,
  }) async {
    final report = ArchiveReport(status: ExtractStatus.running);
    try {
      return await _run(
        report: report,
        archivePath: archivePath,
        password: password,
        type: type,
        onUpdate: onUpdate,
        isCancelled: isCancelled,
      );
    } catch (e) {
      report.status = ExtractStatus.failed;
      report.errorSummary = '解压过程异常: $e';
      onUpdate?.call(report);
      return report;
    }
  }

  Future<ArchiveReport> _run({
    required ArchiveReport report,
    required String archivePath,
    required String password,
    required DetectedFileType type,
    void Function(ArchiveReport)? onUpdate,
    bool Function()? isCancelled,
  }) async {
    if (!supports(type)) {
      report.status = ExtractStatus.skipped;
      report.errorSummary = '该文件类型不参与自动解压';
      onUpdate?.call(report);
      return report;
    }

    onUpdate?.call(report);
    var result = await extractService.extract(
      archivePath: archivePath,
      password: password,
      type: type,
      onProgress: (p) {
        report.progress = p;
        onUpdate?.call(report);
      },
      isCancelled: isCancelled,
    );

    // 什么情况下值得走 ZIP 结构修复？
    //
    // 不能要求"一个文件都没解出来"——7-Zip 在中央目录被毁时**仍能靠扫描
    // 本地头解出文件**，只是会带上 "Unexpected end of archive" 之类的警告、
    // 退出码非 0。那种"解压完成但有警告"的结论对用户毫无用处：他既不知道
    // 文件可不可信，也拿不到一个以后能正常打开的包。
    //
    // 所以判据是"没有干净成功"：既包括彻底失败，也包括带警告的部分成功。
    // 代价是数据块真损坏（CRC 错）时也会多拷一份——但大包有阈值兜底，
    // 小包多留一份修好的包本来就有价值。
    //
    // 密码错误要排除：修结构救不了密码，白拷一份大文件。
    final worthRepairing = type == DetectedFileType.zip &&
        result.status != ExtractStatus.success &&
        !_isWrongPassword(result);

    if (!worthRepairing) {
      _adopt(report, result);
      onUpdate?.call(report);
      return report;
    }

    final repairedPath = await _allocateRepairedPath(archivePath);
    final repair = await ZipRepairService.repair(
      archivePath,
      outputPath: repairedPath,
      onProgress: (p) {
        report.progress = p;
        onUpdate?.call(report);
      },
    );

    if (!repair.succeeded || repair.repairedPath == null) {
      // 修复没成功：保留原始失败结论，但把"试过修复"这个事实写进去，
      // 用户才知道程序做过努力、而不是直接放弃了
      final merged = _withRepair(result, repair);
      _adopt(report, merged);
      onUpdate?.call(report);
      return report;
    }

    final retry = await extractService.extract(
      archivePath: repair.repairedPath!,
      // 目录名以**原包**为准。重试解的是 `xxx_repaired.zip`，若顺着它取名，
      // 用户拿到的是 `xxx_repaired_解压`——"修过"是我们内部的事，不该印在
      // 他的文件夹上。
      outputNameFrom: archivePath,
      password: password,
      type: type,
      onProgress: (p) {
        report.progress = p;
        onUpdate?.call(report);
      },
      isCancelled: isCancelled,
    );

    var finalRepair = repair;
    if (retry.hasUsableOutput) {
      // 首次尝试在结构损坏的包上也留下过一个输出目录（里面可能是残缺或
      // 0 字节的壳文件）。重试成功后就把它删掉——留着会让用户看到两个
      // 文件夹，分不清哪个可信。
      if (result.outputDir.isNotEmpty) {
        await _discardDir(result.outputDir);
      }
      // 首次尝试已占住 `<原名>_解压`，重试只能退让成 `<原名>_解压(1)`。
      // 原目录刚腾空，这里把名字扶正。
      await _promoteOutputDir(retry, archivePath);
      finalRepair = _withRepair(retry, repair).repair!;
    }

    // 阈值：大包只解压、不留修复产物。删掉文件但不抹掉"修过"这个事实，
    // 否则用户会以为修复没发生。
    final sourceSize = await _lengthOf(archivePath);
    if (sourceSize != null && sourceSize > repairedZipSizeLimitBytes) {
      await _deleteQuietly(repair.repairedPath!);
      finalRepair = RepairReport(
        attempted: true,
        succeeded: true,
        repairedPath: null,
        recoveredEntries: repair.recoveredEntries,
        droppedEntries: repair.droppedEntries,
        error: null,
      );
    }

    _adopt(report, _withRepair(retry, finalRepair));
    onUpdate?.call(report);
    return report;
  }

  bool _isWrongPassword(ArchiveReport r) =>
      (r.errorSummary ?? '').contains('密码错误');

  ArchiveReport _withRepair(ArchiveReport base, RepairReport repair) {
    base.repair = repair;
    if (repair.attempted && repair.succeeded && base.hasUsableOutput) {
      base.errorSummary = '原包结构损坏，已重建目录后解出 ${base.files.length} 个文件';
      if (base.status == ExtractStatus.failed) {
        base.status = ExtractStatus.success;
      }
    } else if (repair.attempted && !repair.succeeded) {
      base.errorSummary =
          '${base.errorSummary ?? '解压失败'}；目录重建也未成功（${repair.error ?? ''}）';
    }
    return base;
  }

  void _adopt(ArchiveReport target, ArchiveReport source) {
    target.status = source.status;
    target.outputDir = source.outputDir;
    target.files = source.files;
    target.failed = source.failed;
    target.repair = source.repair;
    target.errorSummary = source.errorSummary;
    target.progress = source.progress;
  }

  Future<String> _allocateRepairedPath(String archivePath) async {
    final sep = Platform.pathSeparator;
    final fileName = archivePath.split(RegExp(r'[/\\]')).last;
    final dot = fileName.lastIndexOf('.');
    final base = dot > 0 ? fileName.substring(0, dot) : fileName;
    final parent = File(archivePath).parent.path;

    var candidate = '$parent$sep${base}_repaired.zip';
    var n = 0;
    while (await File(candidate).exists()) {
      n++;
      candidate = '$parent$sep${base}_repaired($n).zip';
    }
    return candidate;
  }

  Future<int?> _lengthOf(String path) async {
    try {
      final f = File(path);
      return await f.exists() ? await f.length() : null;
    } catch (_) {
      return null;
    }
  }

  Future<void> _deleteQuietly(String path) async {
    try {
      final f = File(path);
      if (await f.exists()) await f.delete();
    } catch (_) {
      // 删不掉不影响解压结果；下次运行会因重名自动加序号，不会覆盖
    }
  }

  /// 把重试的输出目录改回首选名（`<原包名>_解压`）。
  ///
  /// 只在首次尝试的目录腾空之后调用，所以目标名通常正好可用。改名失败
  /// （目录被别的进程占着等）不影响任何结论——序号目录照样能用，只是名字
  /// 难看，不值得为它把已经到手的解压结果判成失败。
  ///
  /// 若首选名仍被别人占着（比如上一次运行留下的目录），就保持现状：那说明
  /// 这个名字确实有主，加序号才是对的。
  Future<void> _promoteOutputDir(
    ArchiveReport retry,
    String originalArchivePath,
  ) async {
    final current = retry.outputDir;
    if (current.isEmpty) return;
    final preferred =
        ArchiveExtractService.preferredOutputDirFor(originalArchivePath);
    if (current == preferred) return;
    try {
      if (await Directory(preferred).exists()) return;
      await Directory(current).rename(preferred);
      retry.outputDir = preferred;
    } catch (_) {
      // 保留序号目录名
    }
  }

  Future<void> _discardDir(String dir) async {
    try {
      final d = Directory(dir);
      if (await d.exists()) await d.delete(recursive: true);
    } catch (_) {
      // 清理失败不影响结论
    }
  }
}
