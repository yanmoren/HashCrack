import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/archive_report.dart';
import 'package:hashcat_gui/models/file_type.dart';
import 'package:hashcat_gui/services/app_paths.dart';
import 'package:hashcat_gui/services/archive_auto_extractor.dart';

import 'support/corrupt_zip.dart';

/// 自动解压编排的测试：覆盖"直接解 → 失败则修 → 重试 → 阈值"整条决策链。
void main() {
  late Directory tmp;
  late String sevenZip;

  setUpAll(() {
    tmp = Directory.systemTemp.createTempSync('autoextract_');
    if (AppPaths.sevenZipExe.isEmpty) {
      fail('AppPaths 未解析到内置 7-Zip');
    }
    sevenZip = AppPaths.sevenZipExe;
  });

  tearDownAll(() {
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  String seed(String dir, String name, {int size = 300}) {
    final f = File('$dir/$name')
      ..createSync(recursive: true)
      ..writeAsBytesSync(Uint8List.fromList(
        List<int>.generate(size, (i) => (i * 17 + 3) % 241),
      ));
    return name;
  }

  void pack(String out, List<String> names, {String? password, bool as7z = false}) {
    final r = Process.runSync(
      sevenZip,
      [
        'a',
        if (as7z) ...['-t7z', '-mhe=on'] else ...['-tzip', '-mx=5'],
        if (password != null) ...['-p$password', if (!as7z) '-mem=ZipCrypto'],
        out,
        ...names,
      ],
      workingDirectory: tmp.path,
    );
    if (r.exitCode != 0) fail('造包失败: ${r.stdout}${r.stderr}');
  }

  int centralDirOffset(String path) {
    final bytes = File(path).readAsBytesSync();
    for (var i = 0; i + 4 <= bytes.length; i++) {
      if (bytes[i] == 0x50 &&
          bytes[i + 1] == 0x4b &&
          bytes[i + 2] == 0x01 &&
          bytes[i + 3] == 0x02) return i;
    }
    return -1;
  }

  test('正常的 ZIP：直接解开，不触发修复', () async {
    seed(tmp.path, 'ok.bin');
    pack('ok.zip', ['ok.bin'], password: 'Test1234');

    final r = await ArchiveAutoExtractor().run(
      archivePath: '${tmp.path}/ok.zip',
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(r.status, ExtractStatus.success, reason: r.errorSummary ?? '');
    expect(r.repair?.attempted, isNot(true), reason: '好包不该走修复链路');
    expect(r.files.single.relativePath, 'ok.bin');
  });

  test('ZIP 目录损坏：自动重建后解出，并如实说明是"重建后解出"', () async {
    seed(tmp.path, 'fix.bin');
    pack('fix.zip', ['fix.bin'], password: 'Test1234');
    final src = '${tmp.path}/fix.zip';
    final raf = File(src).openSync(mode: FileMode.append)
      ..truncateSync(centralDirOffset(src))
      ..closeSync();

    final r = await ArchiveAutoExtractor().run(
      archivePath: src,
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(r.status, ExtractStatus.success, reason: r.errorSummary ?? '');
    expect(r.repair!.attempted, isTrue);
    expect(r.repair!.succeeded, isTrue);
    expect(r.repair!.repairedPath, isNotNull);
    expect(File(r.repair!.repairedPath!).existsSync(), isTrue);
    expect(r.errorSummary, contains('重建'));
    // 内容必须对
    expect(
      File('${r.outputDir}/fix.bin').readAsBytesSync(),
      equals(File('${tmp.path}/fix.bin').readAsBytesSync()),
    );
  });

  test('修复重试的输出目录用原包名，不留 _repaired 与序号痕迹', () async {
    seed(tmp.path, 'nm.bin');
    pack('nm.zip', ['nm.bin'], password: 'Test1234');
    final src = '${tmp.path}/nm.zip';
    File(src).openSync(mode: FileMode.append)
      ..truncateSync(centralDirOffset(src))
      ..closeSync();

    final r = await ArchiveAutoExtractor().run(
      archivePath: src,
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(r.status, ExtractStatus.success, reason: r.errorSummary ?? '');
    expect(r.repair!.succeeded, isTrue, reason: '前提：确实走了修复重试');

    // 重试解的是 `nm_repaired.zip`，但目录名必须回到原包的 `nm_解压`：
    // `_repaired` 是内部实现痕迹，`(1)` 是首次尝试占位留下的残渣。
    final sep = Platform.pathSeparator;
    expect(r.outputDir, '${tmp.path}${sep}nm_解压');
    expect(Directory('${tmp.path}${sep}nm_repaired_解压').existsSync(), isFalse,
        reason: '不该把"修过"印在用户的文件夹名上');
    expect(Directory('${tmp.path}${sep}nm_解压(1)').existsSync(), isFalse,
        reason: '扶正后不该留下序号目录');
    expect(
      File('${r.outputDir}${sep}nm.bin').readAsBytesSync(),
      equals(File('${tmp.path}${sep}nm.bin').readAsBytesSync()),
    );
  });

  test('超大包：仍然解开，但不留修复产物（省磁盘）', () async {
    seed(tmp.path, 'big.bin');
    pack('big.zip', ['big.bin'], password: 'Test1234');
    final src = '${tmp.path}/big.zip';
    File(src).openSync(mode: FileMode.append)
      ..truncateSync(centralDirOffset(src))
      ..closeSync();

    // 阈值设为 1 字节，任何包都算"大包"
    final r = await ArchiveAutoExtractor(repairedZipSizeLimitBytes: 1).run(
      archivePath: src,
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(r.status, ExtractStatus.success, reason: r.errorSummary ?? '');
    expect(r.repair!.repairedPath, isNull, reason: '大包不应留修复产物');
    expect(r.repair!.recoveredEntries, greaterThan(0),
        reason: '不留档不等于"没修过"，事实要保留');
    // 本用例的修复产物不该留在磁盘上（别的用例留下的 _repaired 文件不算）
    expect(
      Directory(tmp.path)
          .listSync()
          .whereType<File>()
          .any((f) => f.path.contains('big_repaired')),
      isFalse,
    );
  });

  test('密码错误：不触发修复（修了也解不开，白拷一份大文件）', () async {
    seed(tmp.path, 'pw.bin');
    pack('pw.zip', ['pw.bin'], password: 'Test1234');

    final r = await ArchiveAutoExtractor().run(
      archivePath: '${tmp.path}/pw.zip',
      password: 'WrongPass',
      type: DetectedFileType.zip,
    );

    expect(r.status, ExtractStatus.failed);
    expect(r.errorSummary, contains('密码错误'));
    expect(r.repair?.attempted, isNot(true));
  });

  test('加密包密文损坏：不得判成密码错误，完好的文件要留下', () async {
    seed(tmp.path, 'g1.bin', size: 800);
    seed(tmp.path, 'g2.bin', size: 800);
    final packed = Process.runSync(
      sevenZip,
      [
        'a', '-tzip', '-mx=0', '-pTest1234', '-mem=ZipCrypto',
        '${tmp.path}/crcenc.zip', 'g1.bin', 'g2.bin',
      ],
      workingDirectory: tmp.path,
    );
    expect(packed.exitCode, 0, reason: packed.stdout + packed.stderr);

    // 密码完全正确，只是 g1.bin 的密文被动过一个字节。7-Zip 无从分辨
    // "密钥错"还是"密文被改过"，会报
    // `CRC Failed in encrypted file. Wrong password?`——若照字面判成密码错误，
    // 就会丢掉完好的 g2.bin，还彻底跳过结构修复。
    flipByteInStoredEntry('${tmp.path}/crcenc.zip', 'g1.bin');

    final r = await ArchiveAutoExtractor().run(
      archivePath: '${tmp.path}/crcenc.zip',
      password: 'Test1234',
      type: DetectedFileType.zip,
    );

    expect(r.errorSummary, isNot(contains('密码错误')), reason: r.errorSummary ?? '');
    expect(r.status, ExtractStatus.partial, reason: r.errorSummary ?? '');
    expect(r.files.map((f) => f.relativePath), contains('g2.bin'),
        reason: '完好的文件不能因为误判而丢');
    expect(r.repair, isNotNull, reason: '数据损坏也必须进修复链路');
  });

  test('7z 损坏：不尝试结构修复（格式没有冗余，真修不了）', () async {
    seed(tmp.path, 'seven.bin');
    pack('seven.7z', ['seven.bin'], password: 'Test1234', as7z: true);
    final f = File('${tmp.path}/seven.7z');
    final bytes = f.readAsBytesSync();
    for (var i = 0; i < 32 && i < bytes.length; i++) {
      bytes[i] = 0;
    }
    f.writeAsBytesSync(bytes);

    final r = await ArchiveAutoExtractor().run(
      archivePath: f.path,
      password: 'Test1234',
      type: DetectedFileType.sevenZip,
    );

    expect(r.status, ExtractStatus.failed);
    expect(r.repair, isNull, reason: '7z 不该进修复链路');
    expect(r.errorSummary, contains('无冗余'));
  });

  test('不参与解压的类型：跳过且不抛异常', () async {
    final r = await ArchiveAutoExtractor().run(
      archivePath: '${tmp.path}/x.pdf',
      password: 'p',
      type: DetectedFileType.pdf,
    );

    expect(r.status, ExtractStatus.skipped);
    expect(ArchiveAutoExtractor.supports(DetectedFileType.pdf), isFalse);
  });

  test('源文件不存在：返回失败报告而不是抛异常', () async {
    final r = await ArchiveAutoExtractor().run(
      archivePath: '${tmp.path}/nope.zip',
      password: 'p',
      type: DetectedFileType.zip,
    );

    expect(r.status, ExtractStatus.failed);
    expect(r.errorSummary, isNotNull);
  });
}
