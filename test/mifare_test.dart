// MIFARE 转储解析 + 密钥候选 + nonce 恢复的集成测试。
//
// 这里刻意不依赖任何外部文件（不读用户机器上的 Dtk.nfc），转储内容全部在
// 测试里现造。因为这条链路上最关键的一个行为是「部分未知」：Flipper 会把读
// 不到的字节写成 `??`，一个尾块里可能只有 Key A 读不到，而访问位和 Key B 是
// 完整的——这正是判断「这个扇区还能不能用 Key B 读」的依据。造一个可控的
// 样本来锁住它，比依赖真实卡片稳定得多。

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/file_type.dart';
import 'package:hashcat_gui/models/mifare.dart';
import 'package:hashcat_gui/models/mifare_keys.dart';
import 'package:hashcat_gui/services/file_identifier.dart';
import 'package:hashcat_gui/services/mifare_service.dart';

/// 造一张 1K 卡的 Flipper 转储文本。
///
/// 布局与真实门禁卡一致：
///   · 扇区 0 是厂商块，Key A / Key B 都是出厂值 FFFFFFFFFFFF
///   · 其余扇区 Key A = ABCD06130904，Key B = FFFFFFFFFFFF，访问位 FF 07 80
///   · [unknownKeyASectors] 里的扇区，Key A 读不出来（写成 `??`）
String _buildFlipperDump({
  required Set<int> unknownKeyASectors,
  String keyA = 'ABCD06130904',
  String keyB = 'FFFFFFFFFFFF',
  String access = 'FF 07 80',
  String uid = 'D2 37 72 02',
}) {
  final sb = StringBuffer();
  sb.writeln('Filetype: Flipper NFC device');
  sb.writeln('Version: 2');
  sb.writeln('Device type: Mifare Classic');
  sb.writeln('UID: $uid');
  sb.writeln('ATQA: 00 04');
  sb.writeln('SAK: 08');
  sb.writeln('Mifare Classic type: 1K');
  sb.writeln('Data format version: 2');

  for (var sector = 0; sector < 16; sector++) {
    for (var i = 0; i < 4; i++) {
      final block = sector * 4 + i;
      final isTrailer = i == 3;
      final List<String> bytes;

      if (!isTrailer) {
        // 数据块：用扇区号+块号造一点可辨识的内容
        bytes = List.generate(16,
            (j) => (0x10 + sector).toRadixString(16).padLeft(2, '0').toUpperCase())
          ..[0] = sector.toRadixString(16).padLeft(2, '0').toUpperCase()
          ..[1] = i.toRadixString(16).padLeft(2, '0').toUpperCase();
      } else {
        final useKeyA = sector == 0 ? 'FFFFFFFFFFFF' : keyA;
        // 关键样本：这些扇区的 Key A 读不出来
        final a = unknownKeyASectors.contains(sector)
            ? List.filled(6, '??')
            : _split(useKeyA);
        bytes = [...a, ...access.split(' '), '69', ..._split(keyB)];
      }
      sb.writeln('Block $block: ${bytes.join(' ')}');
    }
  }
  return sb.toString();
}

List<String> _split(String hex) => [
      for (var i = 0; i < hex.length; i += 2) hex.substring(i, i + 2).toUpperCase(),
    ];

String _writeTemp(String name, String content) {
  final dir = Directory.systemTemp.createTempSync('mifare_test_');
  final f = File('${dir.path}${Platform.pathSeparator}$name');
  f.writeAsStringSync(content);
  return f.path;
}

void main() {
  group('Flipper 转储解析', () {
    late String path;
    late MifareDump dump;

    setUpAll(() async {
      path = _writeTemp('Dtk.nfc', _buildFlipperDump(unknownKeyASectors: {14}));
      dump = await parseMifareDump(path);
    });

    test('卡片基本信息应被正确读出', () {
      expect(dump.format, MifareDumpFormat.flipperNfc);
      expect(dump.fileName, 'Dtk.nfc');
      expect(dump.uidHex, 'D2 37 72 02');
      expect(dump.atqaHex, '00 04', reason: 'ATQA 是两个字节，不能丢掉前导的 00');
      expect(dump.sakHex, '08');
      expect(dump.cardType, '1K');
      expect(dump.sectors.length, 16);
      expect(dump.blockCount, 64);
    });

    test('ATQA 应当整体保留为 0x0004，而不是只剩 0x04', () {
      expect(dump.atqa, 0x0004);
    });

    test('已知的 Key A 应完整读出', () {
      expect(dump.sectors[0].keyA, isNotNull);
      expect(dump.sectors[0].keyA!.length, 6);
      expect(_hex(dump.sectors[1].keyA), 'ABCD06130904');
    });

    test('访问位应为 FF 07 80，并解码为 transport config', () {
      final access = dump.sectors[1].access;
      expect(access, isNotNull);
      expect(access!.consistent, isTrue, reason: '三个字节互为反码，交叉校验应通过');
      // 出厂配置下 Key B 可读，但 NXP 规定不能用它认证
      expect(access.keyBReadable, isTrue);
    });

    test('Key A 读不到的扇区，其 Key B 和访问位仍应保留', () async {
      final s14 = dump.sectors[14];
      expect(s14.keyAKnown, isFalse, reason: '扇区 14 的 Key A 是 ??，应当判为未知');
      expect(s14.keyBKnown, isTrue, reason: '同一尾块里的 Key B 是完整的，不能一起判未知');
      expect(_hex(s14.keyB), 'FFFFFFFFFFFF');
      expect(_hex(s14.accessBytes), 'FF0780');
    });

    test('未知密钥位置应精确到「扇区 14 Key A」', () {
      final unknown = dump.unknownKeySlots;
      expect(unknown.length, 1, reason: '只应有一处密钥未知');
      expect(unknown.single, contains('14'));
      expect(unknown.single, contains('Key A'));
    });

    test('扇区 14 应被判定为不可读，其余扇区可读', () {
      expect(dump.lockedSectors, [14]);

      final v14 = dump.verdictFor(dump.sectors[14]);
      expect(v14.hasUnknownKey, isTrue);
      expect(v14.dataReadable, isFalse);

      final v1 = dump.verdictFor(dump.sectors[1]);
      expect(v1.hasUnknownKey, isFalse);
      expect(v1.dataReadable, isTrue);
    });

    test('报告应点明扇区 14 读不出来，并给出恢复途径', () {
      final report = dump.buildReport();
      expect(report, contains('Dtk.nfc'));
      expect(report, contains('扇区 14'));
      expect(report, contains('mfkey32'));
      // 报告里要明确讲清「dump 不能离线试密钥」这件事，避免误导用户
      expect(report, contains('无法离线试密钥'));
    });
  });

  group('多扇区缺密钥的转储', () {
    test('缺 3 个扇区时应逐个列出', () async {
      final path = _writeTemp(
          'multi.nfc', _buildFlipperDump(unknownKeyASectors: {3, 7, 14}));
      final dump = await parseMifareDump(path);
      expect(dump.lockedSectors, [3, 7, 14]);
      expect(dump.unknownKeySlots.length, 3);
    });

    test('全部扇区都读得出时不应报出任何未知密钥', () async {
      final path = _writeTemp('clean.nfc', _buildFlipperDump(unknownKeyASectors: {}));
      final dump = await parseMifareDump(path);
      expect(dump.lockedSectors, isEmpty);
      expect(dump.unknownKeySlots, isEmpty);
      expect(buildAdvice(dump), contains('不需要再做任何恢复'));
    });
  });

  group('裸二进制转储', () {
    test('1024 字节应解析成 1K 卡的 64 个块', () async {
      final bytes = List<int>.generate(1024, (i) => i & 0xFF);
      final dir = Directory.systemTemp.createTempSync('mifare_raw_');
      final f = File('${dir.path}${Platform.pathSeparator}raw.mfd');
      f.writeAsBytesSync(bytes);

      final dump = await parseMifareDump(f.path);
      expect(dump.format, MifareDumpFormat.rawBin);
      expect(dump.blockCount, 64);
      expect(dump.cardType, '1K');
    });

    test('长度不是 16 的整数倍时应报错', () async {
      final dir = Directory.systemTemp.createTempSync('mifare_bad_');
      final f = File('${dir.path}${Platform.pathSeparator}bad.bin');
      f.writeAsBytesSync(List<int>.filled(100, 0));
      expect(() => parseMifareDump(f.path), throwsA(isA<MifareParseException>()));
    });
  });

  group('密钥候选生成', () {
    test('应合并「转储已知」与「常见默认」两类来源', () async {
      final path = _writeTemp('keys.nfc', _buildFlipperDump(unknownKeyASectors: {14}));
      final dump = await parseMifareDump(path);
      final keys = buildKeyCandidates(dump);

      final values = keys.map((k) => k.key).toList();
      expect(values, contains('ABCD06130904'), reason: '转储里已知的 Key A 要在表里');
      expect(values, contains('FFFFFFFFFFFF'), reason: '出厂默认 Key B 要在表里');
      expect(values.toSet().length, values.length, reason: '不能有重复项');

      final known = keys.where((k) => k.source.contains('转储')).toList();
      expect(known, isNotEmpty);
      expect(known.first.source, contains('扇区'));
    });

    test('导出的字典应当是每行一把 12 位十六进制', () async {
      final path = _writeTemp('keys.nfc', _buildFlipperDump(unknownKeyASectors: {14}));
      final dump = await parseMifareDump(path);
      final content = buildKeysFile(buildKeyCandidates(dump));

      final keyLines = content
          .split('\n')
          .where((l) => l.trim().isNotEmpty && !l.startsWith('#'))
          .toList();
      expect(keyLines, isNotEmpty);
      for (final line in keyLines) {
        expect(RegExp(r'^[0-9A-F]{12}$').hasMatch(line.trim()), isTrue,
            reason: '「$line」不是合法的 12 位十六进制密钥');
      }
    });
  });

  group('nonce 日志解析与密钥恢复', () {
    // Flipper 生成的真实写法：说明文字挂在 cuid 前面
    const flipperLog = '''
Sec 14 key A cuid 2A234F80
nt0 240BD022
nr0 AD2E1687
ar0 57E6F7E4
nt1 18A4BD3E
nr1 ACCC1A23
ar1 6F10E401
''';

    test('应解析出 1 组记录，并保留「Sec 14 key A」这行说明', () {
      final records = parseNonceLogText(flipperLog);
      expect(records.length, 1);
      expect(records.single.uid, 0x2A234F80);
      expect(records.single.nt0, 0x240BD022);
      expect(records.single.ar1, 0x6F10E401);
      expect(records.single.label, contains('Sec 14 key A'),
          reason: '扇区信息写在 cuid 前面，不能被丢掉');
    });

    test('带冒号和 0x 前缀的写法也应能解析', () {
      final records = parseNonceLogText('''
uid: 0x2A234F80
nt0: 240BD022
nr0: AD2E1687
ar0: 57E6F7E4
nt1: 18A4BD3E
nr1: ACCC1A23
ar1: 6F10E401
''');
      expect(records.length, 1);
      expect(records.single.uid, 0x2A234F80);
    });

    test('多组记录应各自成对，标签不串组', () {
      final records = parseNonceLogText('''
Sec 0 key A cuid 2A234F80
nt0 240BD022
nr0 AD2E1687
ar0 57E6F7E4
nt1 18A4BD3E
nr1 ACCC1A23
ar1 6F10E401

Sec 5 key B cuid 2A234F80
nt0 11111111
nr0 22222222
ar0 33333333
nt1 44444444
nr1 55555555
ar1 66666666
''');
      expect(records.length, 2);
      expect(records[0].label, contains('Sec 0 key A'));
      expect(records[1].label, contains('Sec 5 key B'));
      expect(records[1].nt0, 0x11111111);
    });

    test('只有一组 nonce 时不应凑出一条假记录', () {
      final records = parseNonceLogText('''
uid: 2A234F80
nt0: 240BD022
nr0: AD2E1687
ar0: 57E6F7E4
''');
      expect(records, isEmpty, reason: '缺第二组时不完整，不能当成有效记录');
    });

    test('服务的恢复入口应算出 A0A1A2A3A4A5', () async {
      final path = _writeTemp('mfkey32.log', flipperLog);
      final result = await const MifareService().recoverFromNonceLog(path);
      expect(result.success, isTrue);
      expect(result.recoveredKey, 'A0A1A2A3A4A5');
      expect(result.recoveredLabel, contains('Sec 14 key A'));
      expect(result.records.length, 1);
    });

    test('日志里凑不出有效记录时应抛出可读的错误', () async {
      final path = _writeTemp('mfkey32.log', 'nothing useful here\n');
      expect(
        () => const MifareService().recoverFromNonceLog(path),
        throwsA(isA<MifareParseException>()),
      );
    });

    test('文件不存在时应抛出可读的错误', () async {
      expect(
        () => const MifareService()
            .recoverFromNonceLog('Z:/definitely/not/here.log'),
        throwsA(isA<MifareParseException>()),
      );
    });
  });

  group('文件识别分流（整个功能的入口）', () {
    test('Flipper 转储应被识别为 mifareDump', () async {
      final path = _writeTemp('Dtk.nfc', _buildFlipperDump(unknownKeyASectors: {14}));
      expect(await FileIdentifier.identify(path), DetectedFileType.mifareDump);
    });

    test('mfkey32 日志应被识别为 nonceLog', () async {
      final path = _writeTemp('mfkey32.log', '''
Sec 14 key A cuid 2A234F80
nt0 240BD022
nr0 AD2E1687
ar0 57E6F7E4
nt1 18A4BD3E
nr1 ACCC1A23
ar1 6F10E401
''');
      expect(await FileIdentifier.identify(path), DetectedFileType.nonceLog);
    });

    test('nonce 日志不能被误判成哈希文件', () async {
      // `nt0: 240BD022` 这种行和哈希文件的 `用户名:哈希` 长得一模一样，
      // 如果识别顺序反了，用户拖进来的 mfkey32.log 会被送去 hashcat 破解。
      final path = _writeTemp('mfkey32.log', '''
uid: 2A234F80
nt0: 240BD022
nr0: AD2E1687
ar0: 57E6F7E4
nt1: 18A4BD3E
nr1: ACCC1A23
ar1: 6F10E401
''');
      expect(await FileIdentifier.identify(path), DetectedFileType.nonceLog);
    });

    test('1024 字节的裸转储应被识别为 mifareDump', () async {
      final dir = Directory.systemTemp.createTempSync('mifare_ident_');
      final f = File('${dir.path}${Platform.pathSeparator}card.mfd');
      f.writeAsBytesSync(List<int>.filled(1024, 0));
      expect(await FileIdentifier.identify(f.path), DetectedFileType.mifareDump);
    });

    test('普通哈希文件仍应被识别为 hashFile（不能被新分支抢走）', () async {
      final path = _writeTemp('hashes.txt',
          '5f4dcc3b5aa765d61d8327deb882cf99\n098f6bcd4621d373cade4e832627b4f6\n');
      expect(await FileIdentifier.identify(path), DetectedFileType.hashFile);
    });
  });

  group('完整流程', () {
    test('分析 + 导出应产出 4 个文件', () async {
      final path = _writeTemp('full.nfc', _buildFlipperDump(unknownKeyASectors: {14}));
      final service = const MifareService();
      final result = await service.analyze(path);
      expect(result.dump.sectors.length, 16);
      expect(result.candidates, isNotEmpty);
      expect(result.report, isNotEmpty);
      expect(result.advice, isNotEmpty);

      final outDir = Directory.systemTemp.createTempSync('mifare_export_').path;
      final files = await service.exportKeys(outDir, result, 'Dtk');
      expect(files.length, 4);
      for (final p in files) {
        expect(File(p).existsSync(), isTrue, reason: '$p 应当被写出来');
        expect(File(p).lengthSync(), greaterThan(0));
      }
      // 字典文件必须落在可预期的名字上，方便用户直接拖进 Proxmark 目录
      expect(files.first, endsWith('Dtk_keys.txt'));
    });
  });
}

String _hex(List<int>? v) => v == null
    ? '??'
    : v.map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join();
