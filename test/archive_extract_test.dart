import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/archive_report.dart';
import 'package:hashcat_gui/models/file_type.dart';
import 'package:hashcat_gui/services/app_paths.dart';
import 'package:hashcat_gui/services/archive_extract_service.dart';

/// 解压执行器的测试。
///
/// 样本由内置 7-Zip 生成（真包，不是手搓的），验收标准是
/// **解出来的文件与原文件逐字节一致**——"退出码为 0"不等于"内容对"。
void main() {
  late Directory tmp;
  late String sevenZip;
  final service = ArchiveExtractService();

  setUpAll(() {
    tmp = Directory.systemTemp.createTempSync('arcextract_');
    if (AppPaths.sevenZipExe.isEmpty) {
      fail('AppPaths 未解析到内置 7-Zip（应存在 runtime/tools/7zip/7z.exe）');
    }
    sevenZip = AppPaths.sevenZipExe;
  });

  tearDownAll(() {
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  /// 造一个内容可校验的源文件，返回相对名
  String seed(String name, {int size = 512}) {
    File('${tmp.path}/$name')
        .writeAsBytesSync(Uint8List.fromList(
      List<int>.generate(size, (i) => (i * 31 + 7) % 251),
    ));
    return name;
  }

  void pack(String zipPath, List<String> names, {String? password, bool aes7z = false}) {
    final args = <String>[
      'a',
      if (aes7z) ...['-t7z', '-mhe=on'] else ...['-tzip', '-mx=5'],
      if (password != null) ...['-p$password', if (!aes7z) '-mem=ZipCrypto'],
      zipPath,
      ...names,
    ];
    final r = Process.runSync(sevenZip, args, workingDirectory: tmp.path);
    if (r.exitCode != 0) fail('造包失败: ${r.stdout}${r.stderr}');
  }

  test('ZipCrypto 包：密码正确时解出且内容逐字节一致', () async {
    final name = seed('zc.bin');
    pack('zc.zip', [name], password: 'Test1234');

    final report = await service.extract(
      archivePath: '${tmp.path}/zc.zip',
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(report.status, ExtractStatus.success, reason: report.errorSummary ?? '');
    expect(report.files.single.relativePath, 'zc.bin');
    expect(
      File('${report.outputDir}/zc.bin').readAsBytesSync(),
      equals(File('${tmp.path}/$name').readAsBytesSync()),
    );
  });

  test('7z AES（含加密头部）：密码正确时能解开', () async {
    final name = seed('aes.bin');
    pack('aes.7z', [name], password: 'Test1234', aes7z: true);

    final report = await service.extract(
      archivePath: '${tmp.path}/aes.7z',
      password: 'Test1234',
      type: DetectedFileType.sevenZip,
    );

    expect(report.status, ExtractStatus.success, reason: report.errorSummary ?? '');
    expect(
      File('${report.outputDir}/aes.bin').readAsBytesSync(),
      equals(File('${tmp.path}/$name').readAsBytesSync()),
    );
  });

  test('密码错误：如实报告密码错误，不假装成功', () async {
    seed('wp.bin');
    pack('wp.zip', ['wp.bin'], password: 'Test1234');

    final report = await service.extract(
      archivePath: '${tmp.path}/wp.zip',
      password: 'WrongPass',
      type: DetectedFileType.zip,
    );

    expect(report.status, ExtractStatus.failed);
    expect(report.errorSummary, contains('密码错误'));
    expect(report.files, isEmpty);
  });

  test('不参与解压的类型：直接跳过，不报错', () async {
    final report = await service.extract(
      archivePath: '${tmp.path}/whatever.pdf',
      password: 'x',
      type: DetectedFileType.pdf,
    );

    expect(report.status, ExtractStatus.skipped);
    expect(ArchiveExtractService.supports(DetectedFileType.pdf), isFalse);
    expect(ArchiveExtractService.supports(DetectedFileType.zip), isTrue);
    expect(ArchiveExtractService.supports(DetectedFileType.sevenZip), isTrue);
  });

  test('输出目录重名时自动加序号，绝不覆盖已有内容', () async {
    final name = seed('dup.bin');
    pack('dup.zip', [name], password: 'Test1234');

    final first = await service.extract(
      archivePath: '${tmp.path}/dup.zip',
      password: 'Test1234',
      type: DetectedFileType.zip,
    );
    // 往已存在的输出目录里塞一个标记文件，第二次解压不得删掉它
    File('${first.outputDir}/keep_me.txt').writeAsStringSync('不许覆盖');

    final second = await service.extract(
      archivePath: '${tmp.path}/dup.zip',
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(second.outputDir, isNot(first.outputDir));
    expect(second.outputDir, endsWith('(1)'));
    expect(File('${first.outputDir}/keep_me.txt').existsSync(), isTrue,
        reason: '第一次的输出目录必须原样保留');
  });

  test('7z 头部被破坏：明确说明无冗余救不回来，不用模糊措辞掩盖', () async {
    seed('broken.bin');
    pack('broken.7z', ['broken.bin'], password: 'Test1234', aes7z: true);

    // 破坏起始头（7z 的结构信息在尾部，起止头都坏掉才彻底打不开）
    final f = File('${tmp.path}/broken.7z');
    final bytes = f.readAsBytesSync();
    for (var i = 0; i < 32 && i < bytes.length; i++) {
      bytes[i] = 0;
    }
    f.writeAsBytesSync(bytes);

    final report = await service.extract(
      archivePath: f.path,
      password: 'Test1234',
      type: DetectedFileType.sevenZip,
    );

    expect(report.status, ExtractStatus.failed);
    expect(report.errorSummary, contains('无冗余'),
        reason: '7z 损坏必须直说救不回来：${report.errorSummary}');
  });

  test('压缩包不存在：明确报错而不是抛异常', () async {
    final report = await service.extract(
      archivePath: '${tmp.path}/missing.zip',
      password: 'x',
      type: DetectedFileType.zip,
    );

    expect(report.status, ExtractStatus.failed);
    expect(report.errorSummary, contains('不存在'));
  });

  test('解出多个文件时清单完整且带大小', () async {
    final names = [seed('m1.bin', size: 128), seed('m2.bin', size: 256)];
    pack('multi.zip', names, password: 'Test1234');

    final report = await service.extract(
      archivePath: '${tmp.path}/multi.zip',
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(report.status, ExtractStatus.success);
    expect(report.files.length, 2);
    expect(report.totalBytes, 384);
  });
}
