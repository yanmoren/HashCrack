import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/archive_report.dart';

void main() {
  test('完整报告往返后所有字段保持一致', () {
    final original = ArchiveReport(
      status: ExtractStatus.partial,
      outputDir: r'E:\data\包名_解压',
      files: const [
        ExtractedFile(relativePath: 'a.txt', size: 12),
        ExtractedFile(relativePath: r'dir\b.bin', size: 3456),
      ],
      failed: const [FailedEntry(name: 'c.dat', reason: 'CRC 校验失败')],
      repair: const RepairReport(
        attempted: true,
        succeeded: true,
        repairedPath: r'E:\data\包名_repaired.zip',
        recoveredEntries: 2,
        droppedEntries: [FailedEntry(name: 'd.bin', reason: '本地头结构不可信')],
        error: null,
      ),
      errorSummary: '救出 2 个，1 个失败',
      progress: 0.75,
    );

    final restored = ArchiveReport.fromJson(original.toJson());

    expect(restored.status, ExtractStatus.partial);
    expect(restored.outputDir, original.outputDir);
    expect(restored.files.length, 2);
    expect(restored.files[1].relativePath, r'dir\b.bin');
    expect(restored.files[1].size, 3456);
    expect(restored.failed.single.name, 'c.dat');
    expect(restored.failed.single.reason, 'CRC 校验失败');
    expect(restored.errorSummary, original.errorSummary);
    expect(restored.progress, 0.75);
    expect(restored.repair!.attempted, isTrue);
    expect(restored.repair!.succeeded, isTrue);
    expect(restored.repair!.repairedPath, r'E:\data\包名_repaired.zip');
    expect(restored.repair!.recoveredEntries, 2);
    expect(restored.repair!.droppedEntries.single.name, 'd.bin');
  });

  test('repair 为 null 时序列化不报错且往返仍为 null', () {
    final report = ArchiveReport(
      status: ExtractStatus.success,
      outputDir: 'out',
      files: const [ExtractedFile(relativePath: 'x', size: 1)],
    );

    final json = report.toJson();
    expect(json['repair'], isNull);

    expect(ArchiveReport.fromJson(json).repair, isNull);
  });

  test('空清单往返后仍是空清单，不是 null', () {
    final report = ArchiveReport(status: ExtractStatus.failed);
    final restored = ArchiveReport.fromJson(report.toJson());

    expect(restored.files, isEmpty);
    expect(restored.failed, isEmpty);
  });

  test('无法识别的状态字符串回退为 pending，而不是抛异常', () {
    final restored = ArchiveReport.fromJson({
      'status': '未来新增的某个状态',
    });
    expect(restored.status, ExtractStatus.pending);
  });

  test('字段缺失或类型异常时不抛异常', () {
    final restored = ArchiveReport.fromJson({
      'files': [
        {'relativePath': 'a'},
        {'size': 'not a number'},
        'not a map',
      ],
      'failed': null,
    });

    expect(restored.files.length, 2);
    expect(restored.files[0].size, 0);
    expect(restored.files[1].relativePath, '');
    expect(restored.failed, isEmpty);
  });

  test('totalBytes 累加所有解出文件', () {
    final report = ArchiveReport(files: const [
      ExtractedFile(relativePath: 'a', size: 100),
      ExtractedFile(relativePath: 'b', size: 250),
    ]);
    expect(report.totalBytes, 350);
  });

  test('skipped 与 failed 都是终态，pending/running 不是', () {
    expect(ExtractStatus.pending.isTerminal, isFalse);
    expect(ExtractStatus.running.isTerminal, isFalse);
    expect(ExtractStatus.success.isTerminal, isTrue);
    expect(ExtractStatus.partial.isTerminal, isTrue);
    expect(ExtractStatus.failed.isTerminal, isTrue);
    expect(ExtractStatus.skipped.isTerminal, isTrue);
  });

  test('hasUsableOutput 只认「至少解出一个文件」', () {
    expect(ArchiveReport(status: ExtractStatus.failed).hasUsableOutput, isFalse);
    expect(
      ArchiveReport(
        status: ExtractStatus.partial,
        files: const [ExtractedFile(relativePath: 'a', size: 1)],
      ).hasUsableOutput,
      isTrue,
    );
  });
}
