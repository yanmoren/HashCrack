import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/services/zip_repair_service.dart';

/// ZIP 修复器的测试。
///
/// 策略：**不手搓 ZIP 二进制，而是用内置 7-Zip 造真包再动手破坏**。
/// 手搓的样本只能证明"我按自己的理解写对了"，而真实打包器产出的结构
/// （extra 字段、标志位、时间戳）才是修复器要面对的东西。
/// 修复产物的验收也交给 7-Zip——它说能打开才算真能打开。
void main() {
  late Directory tmp;
  late String sevenZip;

  setUpAll(() {
    tmp = Directory.systemTemp.createTempSync('ziprepair_');
    final exe = File('runtime/tools/7zip/7z.exe');
    if (!exe.existsSync()) {
      fail('缺少内置 7-Zip：${exe.absolute.path}（应先执行 Task 1）');
    }
    sevenZip = exe.absolute.path;
  });

  tearDownAll(() {
    if (tmp.existsSync()) tmp.deleteSync(recursive: true);
  });

  /// 用 7-Zip 造一个压缩包
  void makeZip(String zipPath, List<String> files, {String? password}) {
    final args = <String>[
      'a',
      '-tzip',
      '-mx=5',
      if (password != null) ...['-p$password', '-mem=ZipCrypto'],
      zipPath,
      ...files,
    ];
    final r = Process.runSync(sevenZip, args, workingDirectory: tmp.path);
    if (r.exitCode != 0) fail('造包失败: ${r.stdout}\n${r.stderr}');
  }

  /// 让 7-Zip 自检压缩包的完整性
  bool sevenZipCanOpen(String zipPath, {String? password}) {
    final r = Process.runSync(
      sevenZip,
      ['t', if (password != null) '-p$password', zipPath],
      workingDirectory: tmp.path,
    );
    return r.exitCode == 0;
  }

  /// 造一个含 [count] 个文件的包。
  ///
  /// 返回**相对文件名**：给 7-Zip 传绝对路径会让包内条目带上完整路径
  /// （甚至盘符），解压时就会多套一层目录，比对文件名会全部对不上。
  List<String> seedFiles(String prefix, int count) {
    final names = <String>[];
    for (var i = 0; i < count; i++) {
      File('${tmp.path}/$prefix$i.txt')
        ..createSync(recursive: true)
        ..writeAsStringSync('内容 $prefix$i\n${'x' * (100 + i * 37)}\n');
      names.add('$prefix$i.txt');
    }
    return names;
  }

  /// 找到中央目录起始偏移（第一个 `PK\x01\x02`）。找不到返回 -1。
  int centralDirOffset(String path) {
    final bytes = File(path).readAsBytesSync();
    for (var i = 0; i + 4 <= bytes.length; i++) {
      if (bytes[i] == 0x50 &&
          bytes[i + 1] == 0x4b &&
          bytes[i + 2] == 0x01 &&
          bytes[i + 3] == 0x02) {
        return i;
      }
    }
    return -1;
  }

  /// 把文件截断到 [length] 字节（模拟下载中断、尾部损坏）
  void truncateTo(String path, int length) {
    final raf = File(path).openSync(mode: FileMode.append);
    raf.truncateSync(length);
    raf.closeSync();
  }

  test('包本身是好的：不做修复、不产生输出文件', () async {
    final src = '${tmp.path}/healthy.zip';
    makeZip(src, seedFiles('h', 3));
    final out = '${tmp.path}/healthy_repaired.zip';

    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.attempted, isFalse, reason: '好包不该走修复链路');
    expect(report.succeeded, isTrue);
    expect(report.recoveredEntries, 3);
    expect(report.repairedPath, isNull);
    expect(File(out).existsSync(), isFalse,
        reason: '不修就不该白拷一份，大包白拷的代价是几 GB');
  });

  test('中央目录整体被删除：扫描本地头重建，产物可被 7-Zip 打开', () async {
    final src = '${tmp.path}/nocd.zip';
    makeZip(src, seedFiles('n', 4));
    final cdStart = centralDirOffset(src);
    expect(cdStart, greaterThan(0));
    truncateTo(src, cdStart); // 砍掉整个中央目录与 EOCD

    expect(sevenZipCanOpen(src), isFalse, reason: '前提：损坏后原包确实打不开');

    final out = '${tmp.path}/nocd_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.attempted, isTrue);
    expect(report.succeeded, isTrue, reason: report.error ?? '');
    expect(report.recoveredEntries, 4);
    expect(report.repairedPath, out);
    expect(sevenZipCanOpen(out), isTrue, reason: '产物必须能被 7-Zip 正常打开');
  });

  test('EOCD 被截断：仍能重建', () async {
    final src = '${tmp.path}/truncated.zip';
    makeZip(src, seedFiles('t', 2));
    final size = File(src).lengthSync();
    truncateTo(src, size - 10); // 砍掉 EOCD 尾部

    final out = '${tmp.path}/truncated_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.succeeded, isTrue, reason: report.error ?? '');
    expect(report.recoveredEntries, 2);
    expect(sevenZipCanOpen(out), isTrue);
  });

  test('压缩数据里含 PK\\x03\\x04 字面量时不会误判成条目', () async {
    // 不压缩存盘（-mx=0），保证那串字节原样留在数据区里
    final payload = File('${tmp.path}/tricky.bin')
      ..writeAsBytesSync(
        Uint8List.fromList([
          0x50, 0x4b, 0x03, 0x04, // 假本地头签名
          0x14, 0x00, 0x00, 0x00,
          ...List.filled(200, 0x41),
          0x50, 0x4b, 0x03, 0x04, // 再来一个
          ...List.filled(100, 0x42),
        ]),
      );

    final src = '${tmp.path}/tricky.zip';
    final r = Process.runSync(
      sevenZip,
      ['a', '-tzip', '-mx=0', src, payload.path],
      workingDirectory: tmp.path,
    );
    expect(r.exitCode, 0, reason: r.stdout + r.stderr);

    final cdStart = centralDirOffset(src);
    truncateTo(src, cdStart);

    final out = '${tmp.path}/tricky_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.succeeded, isTrue, reason: report.error ?? '');
    expect(report.recoveredEntries, 1,
        reason: '只应有 1 个真实条目，假签名不得被当成条目');
    expect(sevenZipCanOpen(out), isTrue);
  });

  test('加密包：修复不改动密文，修复后用原密码仍能解出', () async {
    final files = seedFiles('e', 3);
    final src = '${tmp.path}/enc.zip';
    makeZip(src, files, password: 'Test1234');

    final cdStart = centralDirOffset(src);
    truncateTo(src, cdStart);

    final out = '${tmp.path}/enc_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);
    expect(report.succeeded, isTrue, reason: report.error ?? '');

    // 用原密码解压修复产物，并逐字节比对内容
    final exDir = '${tmp.path}/enc_out';
    final r = Process.runSync(
      sevenZip,
      ['x', '-pTest1234', '-o$exDir', '-y', out],
      workingDirectory: tmp.path,
    );
    expect(r.exitCode, 0, reason: '修复产物应能用原密码解开：${r.stdout}');

    for (final name in files) {
      final original = File('${tmp.path}/$name').readAsBytesSync();
      final restored = File('$exDir/$name').readAsBytesSync();
      expect(restored, equals(original), reason: '$name 内容必须逐字节一致');
    }
  });

  test('完全不是 ZIP 的文件：明确失败，不假装成功', () async {
    final src = File('${tmp.path}/notzip.bin')
      ..writeAsBytesSync(Uint8List.fromList(List.filled(4096, 0x33)));

    final report = await ZipRepairService.repair(
      src.path,
      outputPath: '${tmp.path}/notzip_repaired.zip',
    );

    expect(report.attempted, isTrue);
    expect(report.succeeded, isFalse);
    expect(report.error, isNotNull);
    expect(report.repairedPath, isNull);
  });

  test('源文件不存在：返回明确错误而不是抛异常', () async {
    final report = await ZipRepairService.repair(
      '${tmp.path}/definitely_missing.zip',
      outputPath: '${tmp.path}/x.zip',
    );

    expect(report.attempted, isTrue);
    expect(report.succeeded, isFalse);
    expect(report.error, contains('不存在'));
  });

  test('修复产物自校验：条目数必须与重建数量一致', () async {
    final src = '${tmp.path}/selfcheck.zip';
    makeZip(src, seedFiles('s', 5));
    truncateTo(src, centralDirOffset(src));

    final out = '${tmp.path}/selfcheck_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.succeeded, isTrue);
    expect(report.recoveredEntries, 5);
    // 用 7-Zip 的技术列表（-slt）独立确认条目数：数 "Path = " 行，
    // 比数普通列表里的文件名可靠（普通列表的 Name 列不含路径片段）。
    final listing = Process.runSync(sevenZip, ['l', '-slt', out]);
    final entries = listing.stdout
        .toString()
        .split('\n')
        .where((l) => l.trimLeft().startsWith('Path = ') && l.contains('.txt'))
        .length;
    expect(entries, 5, reason: '7-Zip 应列出 5 个条目');
  });

  // ───────── 以下三例取自真实损坏样本「夫妻GAME.7z#」的结构特征 ─────────

  test('含目录条目：零长度目录不得吞掉后续文件', () async {
    Directory('${tmp.path}/sub').createSync(recursive: true);
    File('${tmp.path}/sub/a.txt').writeAsStringSync('A' * 500);
    File('${tmp.path}/sub/b.txt').writeAsStringSync('B' * 700);

    final src = '${tmp.path}/withdir.zip';
    final r = Process.runSync(
      sevenZip,
      ['a', '-tzip', '-mx=0', src, 'sub'],
      workingDirectory: tmp.path,
    );
    expect(r.exitCode, 0, reason: r.stdout + r.stderr);

    truncateTo(src, centralDirOffset(src));

    final out = '${tmp.path}/withdir_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.succeeded, isTrue, reason: report.error ?? '');
    expect(report.recoveredEntries, 3, reason: '1 个目录条目 + 2 个文件');
    expect(sevenZipCanOpen(out), isTrue);

    // 目录条目的压缩长度是 0，若被误判成"长度未知"，它会一直延伸到文件尾，
    // 把后面两个文件整段吞掉——产物照样能打开，但只剩一条巨型记录。
    // 因此这里必须逐条确认文件真的还在，只看"能打开"会漏掉这个错误。
    final listing = Process.runSync(sevenZip, ['l', '-slt', out]).stdout.toString();
    expect(listing, contains('a.txt'));
    expect(listing, contains('b.txt'));
  });

  test('包前有伪装数据：中央目录偏移整体失效后仍能重建', () async {
    final files = seedFiles('p', 3);
    final plain = '${tmp.path}/plain.zip';
    makeZip(plain, files);

    // 真实样本就是在 ZIP 前塞了一段 MP4 头（1,187,694 字节），
    // 中央目录里记的本地头偏移全部指向错误位置。
    final prefix = Uint8List.fromList([
      0x00, 0x00, 0x00, 0x20,
      ...'ftypisom'.codeUnits,
      ...List.filled(64 * 1024, 0x00),
    ]);
    final src = '${tmp.path}/prefixed.zip';
    final sink = File(src).openSync(mode: FileMode.write);
    sink.writeFromSync(prefix);
    sink.writeFromSync(File(plain).readAsBytesSync());
    sink.closeSync();

    expect(sevenZipCanOpen(src), isFalse, reason: '前提：偏移失效后原包打不开');

    final out = '${tmp.path}/prefixed_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);

    expect(report.attempted, isTrue);
    expect(report.succeeded, isTrue, reason: report.error ?? '');
    expect(report.recoveredEntries, 3);
    expect(sevenZipCanOpen(out), isTrue);

    // 逐字节比对：证明定界用的是真实数据起点，而不是照抄失效的偏移
    final exDir = '${tmp.path}/prefixed_out';
    final x = Process.runSync(
      sevenZip,
      ['x', '-o$exDir', '-y', out],
      workingDirectory: tmp.path,
    );
    expect(x.exitCode, 0, reason: x.stdout + x.stderr);
    for (final name in files) {
      expect(
        File('$exDir/$name').readAsBytesSync(),
        equals(File('${tmp.path}/$name').readAsBytesSync()),
        reason: '$name 内容必须逐字节一致',
      );
    }
  });

  test('存储方法 + ZipCrypto + UTF-8 中文名：修复后原密码仍能逐字节解出', () async {
    Directory('${tmp.path}/u').createSync(recursive: true);
    File('${tmp.path}/u/中文名.txt').writeAsStringSync('中文内容 ${'x' * 300}');
    File('${tmp.path}/u/plain.txt').writeAsStringSync('plain ${'y' * 200}');

    // -mx=0 存储、-mcu=on 置 UTF-8 标志——这两点与真实样本一致
    // （样本条目标志为 0x801：加密位 + UTF-8 位）。
    final src = '${tmp.path}/encu.zip';
    final r = Process.runSync(
      sevenZip,
      [
        'a', '-tzip', '-mx=0', '-mcu=on',
        '-pTest1234', '-mem=ZipCrypto', src, 'u',
      ],
      workingDirectory: tmp.path,
    );
    expect(r.exitCode, 0, reason: r.stdout + r.stderr);

    truncateTo(src, centralDirOffset(src));

    final out = '${tmp.path}/encu_repaired.zip';
    final report = await ZipRepairService.repair(src, outputPath: out);
    expect(report.succeeded, isTrue, reason: report.error ?? '');
    expect(report.recoveredEntries, 3, reason: '1 个目录条目 + 2 个文件');

    final exDir = '${tmp.path}/encu_out';
    final x = Process.runSync(
      sevenZip,
      ['x', '-pTest1234', '-o$exDir', '-y', out],
      workingDirectory: tmp.path,
    );
    expect(x.exitCode, 0, reason: '修复产物应能用原密码解开：${x.stdout}${x.stderr}');

    // 名字按原字节搬运 + 标志位保留，7-Zip 才能正确还原中文名
    expect(
      File('$exDir/u/中文名.txt').readAsBytesSync(),
      equals(File('${tmp.path}/u/中文名.txt').readAsBytesSync()),
    );
    expect(
      File('$exDir/u/plain.txt').readAsBytesSync(),
      equals(File('${tmp.path}/u/plain.txt').readAsBytesSync()),
    );
  });
}
