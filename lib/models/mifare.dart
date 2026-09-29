// MIFARE Classic 转储文件的解析与安全分析。
//
// 支持三种常见的「转储」载体：
//   1. Flipper Zero 的 .nfc / .shd（文本，`Block N: XX XX ...`，未知字节写作 `??`）
//   2. Proxmark3 / mfoc 的 .eml（每行 16 字节十六进制）
//   3. 裸 .bin / .mfd（1024 或 4096 字节）
//
// 必须说清楚的一件事：**转储里没有可验证的东西**。卡片认证通过后读到的是
// 明文，dump 里既没有密文也没有 nonce，所以无法用它离线去「试」候选密钥——
// 试错了也没有靶子告诉你错了。要恢复未知密钥只有两条路：
//   a) 拿实体卡做 nested / hard-nested 攻击（需要已知任意一个密钥）
//   b) 用 mfkey32：抓两次认证的 nonce，离线反推（见 crypto1.dart）
// 本文件负责把「哪把钥匙已知、哪把未知、数据能不能读」摊开讲清楚，
// 并生成上面两条路所需要的钥匙表与命令。
//
// 关键设计：Flipper 会把读不到的字节写成 `??`。一个 16 字节的尾块里可能只有
// 前 6 字节（Key A）读不到，而访问位和 Key B 是完整的——这正好是判断「这个
// 扇区还能不能用 Key B 读」的依据。所以这里按**字节**记录未知状态，而不是
// 把整块判成未知。

import 'dart:io';
import 'dart:typed_data';

/// 转储载体的格式
enum MifareDumpFormat {
  flipperNfc('Flipper Zero 转储 (.nfc/.shd)'),
  proxmarkEml('Proxmark/mfoc 转储 (.eml)'),
  rawBin('裸二进制转储 (.bin/.mfd)');

  const MifareDumpFormat(this.label);
  final String label;
}

/// 一个块的读取状态
enum MifareBlockState {
  present('有数据'),
  allZero('全 0'),
  allFf('全 FF'),
  partial('部分未知'),
  unknown('未知');

  const MifareBlockState(this.label);
  final String label;
}

/// 单个数据块。`unknown[i] == true` 表示第 i 字节读不到（Flipper 记作 `??`）。
class MifareBlock {
  final int index;

  /// 16 字节；null 表示整块未知
  final List<int>? data;

  /// 逐字节未知掩码；null 表示全部已知
  final List<bool>? unknown;

  MifareBlock(this.index, this.data, [this.unknown]);

  bool get isKnown => data != null;
  bool get isFullyUnknown => data == null || (unknown != null && unknown!.every((u) => u));

  bool byteKnown(int i) {
    if (data == null) return false;
    if (unknown == null) return true;
    return !unknown![i];
  }

  /// 第 i 字节；未知返回 null
  int? byte(int i) => byteKnown(i) ? data![i] : null;

  /// 第 [start, endExclusive) 段；只要有一个字节未知就返回 null
  List<int>? slice(int start, int endExclusive) {
    for (var i = start; i < endExclusive; i++) {
      if (!byteKnown(i)) return null;
    }
    return data!.sublist(start, endExclusive);
  }

  MifareBlockState get state {
    if (isFullyUnknown) return MifareBlockState.unknown;
    var anyUnknown = false;
    var allZero = true;
    var allFf = true;
    for (var i = 0; i < 16; i++) {
      if (!byteKnown(i)) {
        anyUnknown = true;
        continue;
      }
      final b = data![i];
      if (b != 0) allZero = false;
      if (b != 0xFF) allFf = false;
    }
    if (allZero) return MifareBlockState.allZero;
    if (allFf) return MifareBlockState.allFf;
    if (anyUnknown) return MifareBlockState.partial;
    return MifareBlockState.present;
  }

  String get hex {
    if (data == null) return '??';
    return List.generate(16, (i) => byteKnown(i) ? _hex2(data![i]) : '??')
        .join(' ');
  }

  /// 去掉空格的一行十六进制（导出用，未知字节记 00）
  String get hexRaw {
    if (data == null) return '';
    return List.generate(16, (i) => _hex2(data![i])).join();
  }
}

/// 一个扇区
class MifareSector {
  final int index;
  final List<MifareBlock> blocks;
  final MifareBlock? trailerBlock;

  MifareSector(this.index, this.blocks, this.trailerBlock);

  int get trailerIndex =>
      trailerBlock?.index ?? (index < 32 ? index * 4 + 3 : 128 + (index - 32) * 16 + 15);

  List<MifareBlock> get dataBlocks {
    final t = trailerBlock;
    if (t == null) return blocks;
    return blocks.where((b) => b.index != t.index).toList();
  }

  /// Key A（尾块 0-5 字节）；有任一字节未知则视为未知
  List<int>? get keyA => trailerBlock?.slice(0, 6);

  /// Key B（尾块 10-15 字节）
  List<int>? get keyB => trailerBlock?.slice(10, 16);

  /// 访问位（尾块 6-8 字节）
  List<int>? get accessBytes => trailerBlock?.slice(6, 9);

  /// 尾块第 9 字节（通用数据，出厂值 0x69）
  int? get userByte => trailerBlock?.byte(9);

  bool get keyAKnown => keyA != null;
  bool get keyBKnown => keyB != null;

  MifareAccessBits? get access => MifareAccessBits.decode(accessBytes);
}

/// 访问位解码结果
class MifareAccessBits {
  /// 第 i 位（bit i）对应扇区内第 i 个块，i=0..2 是数据块，i=3 是尾块
  final int c1;
  final int c2;
  final int c3;

  /// 三个字节互为反码的交叉校验是否通过
  final bool consistent;

  const MifareAccessBits(this.c1, this.c2, this.c3, this.consistent);

  /// 解码规则（NXP MF1S50 手册，尾块 6/7/8 字节）：
  ///
  ///   字节6: ~C2_3 ~C2_2 ~C2_1 ~C2_0 | ~C1_3 ~C1_2 ~C1_1 ~C1_0
  ///   字节7:  C1_3  C1_2  C1_1  C1_0 | ~C3_3 ~C3_2 ~C3_1 ~C3_0
  ///   字节8:  C3_3  C3_2  C3_1  C3_0 |  C2_3  C2_2  C2_1  C2_0
  ///
  /// 每个 bit 存两遍（一遍原码一遍反码）供芯片自检，可以交叉验证。
  /// 出厂默认 `FF 07 80` 解出来是 C1=C2=0、C3=0b1000（只有尾块的 C3 为 1）。
  static MifareAccessBits? decode(List<int>? b) {
    if (b == null || b.length < 3) return null;
    final b6 = b[0], b7 = b[1], b8 = b[2];

    var c1 = 0, c2 = 0, c3 = 0;
    var ok = true;
    for (var i = 0; i < 4; i++) {
      final c1a = (~(b6 >> i)) & 1; // 字节6 低半字节（取反）
      final c1b = (b7 >> (4 + i)) & 1; // 字节7 高半字节（原码）
      if (c1a != c1b) ok = false;

      final c2a = (~(b6 >> (4 + i))) & 1;
      final c2b = (b8 >> i) & 1;
      if (c2a != c2b) ok = false;

      final c3a = (~(b7 >> i)) & 1;
      final c3b = (b8 >> (4 + i)) & 1;
      if (c3a != c3b) ok = false;

      c1 |= (c1a & 1) << i;
      c2 |= (c2a & 1) << i;
      c3 |= (c3a & 1) << i;
    }
    return MifareAccessBits(c1, c2, c3, ok);
  }

  /// 第 blockInSector 块（0-2 数据块，3 尾块）的 C1C2C3
  int codeAt(int blockInSector) => (((c1 >> blockInSector) & 1) << 2) |
      (((c2 >> blockInSector) & 1) << 1) |
      ((c3 >> blockInSector) & 1);

  /// 数据块访问条件 → [读, 写, 加, 减]
  List<String> dataAccessAt(int blockInSector) =>
      _dataAccess[codeAt(blockInSector)] ?? const ['?', '?', '?', '?'];

  /// 尾块访问条件 → [KeyA写, 访问位读, 访问位写, KeyB读, KeyB写]
  List<String> trailerAccess() =>
      _trailerAccess[codeAt(3)] ?? const ['?', '?', '?', '?', '?'];

  /// KeyB 是否可以被读出来。可读就意味着它不再是秘密，
  /// NXP 规定这种配置下不能用它做认证（认证后卡片还会拒绝后续访问）。
  bool get keyBReadable => codeAt(3) == 0x0 || codeAt(3) == 0x1;

  String describeTrailer() {
    final a = trailerAccess();
    final code = codeAt(3).toRadixString(2).padLeft(3, '0');
    return 'C1C2C3=$code  KeyA写=${a[0]} 访问位读=${a[1]} 访问位写=${a[2]} '
        'KeyB读=${a[3]} KeyB写=${a[4]}';
  }

  static const Map<int, List<String>> _dataAccess = {
    0x0: ['A|B', 'A|B', 'A|B', 'A|B'],
    0x2: ['A|B', '禁止', '禁止', '禁止'],
    0x4: ['A|B', 'B', '禁止', '禁止'],
    0x6: ['A|B', 'B', 'B', 'A|B'],
    0x1: ['A|B', '禁止', '禁止', 'A|B'],
    0x3: ['B', 'B', '禁止', '禁止'],
    0x5: ['B', '禁止', '禁止', '禁止'],
    0x7: ['禁止', '禁止', '禁止', '禁止'],
  };

  static const Map<int, List<String>> _trailerAccess = {
    0x0: ['A', 'A', '禁止', 'A', 'A'],
    0x2: ['禁止', 'A', '禁止', 'A', '禁止'],
    0x4: ['B', 'A|B', '禁止', 'A|B', 'B'],
    0x6: ['禁止', 'A|B', '禁止', 'A|B', '禁止'],
    0x1: ['A', 'A', 'A', 'A', 'A'],
    0x3: ['B', 'A|B', 'B', '禁止', 'B'],
    0x5: ['禁止', 'A|B', 'B', '禁止', 'B'],
    0x7: ['禁止', 'A|B', '禁止', '禁止', '禁止'],
  };
}

/// 一个扇区的可访问性结论
class MifareSectorVerdict {
  final MifareSector sector;
  final List<String> usableAuthKeys;
  final List<String> unusableAuthKeys;
  final bool hasUnknownKey;
  final bool dataReadable;
  final List<String> notes;

  const MifareSectorVerdict({
    required this.sector,
    required this.usableAuthKeys,
    required this.unusableAuthKeys,
    required this.hasUnknownKey,
    required this.dataReadable,
    required this.notes,
  });
}

/// 一份转储
class MifareDump {
  final String fileName;
  final MifareDumpFormat format;
  final List<int> uid;
  final int? atqa;
  final int? sak;
  final String cardType;
  final List<MifareBlock> blocks;
  final List<MifareSector> sectors;
  final List<String> parseNotes;

  MifareDump({
    required this.fileName,
    required this.format,
    required this.uid,
    required this.atqa,
    required this.sak,
    required this.cardType,
    required this.blocks,
    required this.sectors,
    required this.parseNotes,
  });

  int get blockCount => blocks.length;
  String get uidHex => uid.map(_hex2).join(' ');

  String get atqaHex => atqa == null
      ? '?'
      : '${_hex2((atqa! >> 8) & 0xFF)} ${_hex2(atqa! & 0xFF)}';

  String get sakHex => sak == null ? '?' : _hex2(sak!);

  /// 所有已知密钥（去重）
  List<String> get knownKeys {
    final seen = <String>{};
    final out = <String>[];
    for (final s in sectors) {
      for (final k in [s.keyA, s.keyB]) {
        if (k == null) continue;
        final h = k.map(_hex2).join().toUpperCase();
        if (seen.add(h)) out.add(h);
      }
    }
    return out;
  }

  /// 未知密钥位置（含「已知但不能用于认证」的 KeyB）
  List<String> get unknownKeySlots {
    final out = <String>[];
    for (final s in sectors) {
      if (!s.keyAKnown) out.add('扇区 ${s.index} Key A');
      if (!s.keyBKnown) out.add('扇区 ${s.index} Key B');
    }
    return out;
  }

  /// 真正「拿不到钥匙、也读不到数据」的扇区
  List<int> get lockedSectors {
    final out = <int>[];
    for (final s in sectors) {
      final v = verdictFor(s);
      if (v.usableAuthKeys.isEmpty) out.add(s.index);
    }
    return out;
  }

  MifareSectorVerdict verdictFor(MifareSector s) {
    final a = s.access;
    final keyA = s.keyA;
    final keyB = s.keyB;

    final usable = <String>[];
    final unusable = <String>[];
    final notes = <String>[];

    if (keyA != null) {
      usable.add('Key A = ${keyA.map(_hex2).join().toUpperCase()}');
    }
    if (keyB != null) {
      final h = keyB.map(_hex2).join().toUpperCase();
      if (a != null && a.keyBReadable) {
        unusable.add('Key B = $h');
        notes.add('访问位是 ${a.codeAt(3).toRadixString(2).padLeft(3, '0')}，'
            '属于出厂 / 运输出厂配置：KeyB 可被读出。NXP 规定这种配置下 KeyB '
            '不能用于认证，认证后卡片还会拒绝后续读写——所以它是已知的，'
            '但**不能当钥匙用**。');
      } else {
        usable.add('Key B = $h');
      }
    }

    if (keyA == null) {
      notes.add('Key A 读不到（转储里是 `??`）。Key A 在卡片上设计上永远不可读，'
          '这是正常现象，不是文件损坏——只能靠 nested 或 mfkey32 攻击恢复。');
    }
    if (keyB == null) {
      notes.add('Key B 读不到。');
    }

    var readable = false;
    if (usable.isNotEmpty) {
      if (a == null) {
        readable = true; // 访问位读不到时不臆断
      } else {
        for (var i = 0; i < 3; i++) {
          final cond = a.dataAccessAt(i)[0];
          if (cond == 'A|B') {
            readable = true;
          } else if (cond == 'A' && keyA != null) {
            readable = true;
          } else if (cond == 'B' && keyB != null && !a.keyBReadable) {
            readable = true;
          }
        }
      }
    }

    return MifareSectorVerdict(
      sector: s,
      usableAuthKeys: usable,
      unusableAuthKeys: unusable,
      hasUnknownKey: keyA == null || keyB == null,
      dataReadable: readable,
      notes: notes,
    );
  }

  /// 生成人类可读的诊断报告
  String buildReport() {
    final sb = StringBuffer();
    sb.writeln('MIFARE Classic 转储分析报告');
    sb.writeln('=' * 46);
    sb.writeln('文件      : $fileName');
    sb.writeln('格式      : ${format.label}');
    sb.writeln('卡型      : $cardType（${blocks.length} 块 / ${sectors.length} 扇区）');
    sb.writeln('UID       : $uidHex');
    sb.writeln('ATQA      : $atqaHex');
    sb.writeln('SAK       : $sakHex'
        '${sak == 0x08 ? '（MIFARE Classic 1K）' : sak == 0x18 ? '（MIFARE Classic 4K）' : ''}');
    sb.writeln();

    final locked = lockedSectors;
    final unknowns = unknownKeySlots;
    sb.writeln('结论');
    sb.writeln('-' * 46);
    if (unknowns.isEmpty) {
      sb.writeln('全部 ${sectors.length} 个扇区的密钥都已拿到'
          '（共 ${knownKeys.length} 把不同的钥匙），无需任何恢复。');
    } else {
      sb.writeln('密钥未知位置共 ${unknowns.length} 处：${unknowns.join('、')}');
      if (locked.isEmpty) {
        sb.writeln('但每个扇区都还有可用密钥，数据仍然读得出来。');
      } else {
        sb.writeln('其中 ${locked.length} 个扇区**没有可用钥匙**（数据读不出来）：'
            '${locked.map((e) => '扇区 $e').join('、')}');
      }
    }
    sb.writeln();

    if (parseNotes.isNotEmpty) {
      sb.writeln('解析提示');
      sb.writeln('-' * 46);
      for (final n in parseNotes) {
        sb.writeln('  · $n');
      }
      sb.writeln();
    }

    sb.writeln('逐扇区明细');
    sb.writeln('-' * 46);
    for (final s in sectors) {
      final v = verdictFor(s);
      final a = s.access;
      sb.writeln('[扇区 ${s.index.toString().padLeft(2)}] 尾块 ${s.trailerIndex}');
      sb.writeln('  Key A : ${s.keyA == null ? '?? （未知）' : s.keyA!.map(_hex2).join().toUpperCase()}');
      sb.writeln('  Key B : ${s.keyB == null ? '?? （未知）' : s.keyB!.map(_hex2).join().toUpperCase()}');
      if (a != null) {
        sb.writeln('  访问位: ${s.accessBytes!.map(_hex2).join(' ')}'
            '  C1=${_bits(a.c1)} C2=${_bits(a.c2)} C3=${_bits(a.c3)}'
            '${a.consistent ? '' : '  ⚠ 反码校验不一致（转储可能被人为改写）'}');
        sb.writeln('    尾块: ${a.describeTrailer()}');
        sb.writeln('    数据块读权限（块0/1/2）: '
            '${List.generate(3, (i) => a.dataAccessAt(i)[0]).join(' / ')}');
      } else {
        sb.writeln('  访问位: ?? （读不到）');
      }
      sb.writeln('  数据块: ${dataSummary(s)}');
      sb.writeln('  可用认证密钥: ${v.usableAuthKeys.isEmpty ? '无' : v.usableAuthKeys.join('、')}');
      if (v.unusableAuthKeys.isNotEmpty) {
        sb.writeln('  已知但不可认证: ${v.unusableAuthKeys.join('、')}');
      }
      sb.writeln('  数据可读: ${v.dataReadable ? '是' : '否'}');
      if (s.userByte != null) {
        sb.writeln('  尾块用户字节: ${_hex2(s.userByte!)}');
      }
      for (final n in v.notes) {
        sb.writeln('  说明: $n');
      }
      sb.writeln();
    }

    sb.writeln('=' * 46);
    sb.writeln('重要说明');
    sb.writeln('-' * 46);
    sb.writeln('· 转储文件里既没有密文也没有 nonce，因此**无法离线试密钥**——'
        '猜错了没有任何东西能告诉你错了。本报告只能告诉你「哪把钥匙已知、'
        '哪把未知、数据能不能读」。');
    sb.writeln('· 要真正拿到未知密钥，只有两条路：');
    sb.writeln('  a) 实体卡 + nested / hard-nested 攻击：只要知道同一张卡上任意一个密钥，'
        '就能在几秒内算出其余密钥。本卡已知钥匙充足，这条路成功率很高。');
    sb.writeln('  b) mfkey32：抓两次认证的 nonce，完全离线反推密钥。');
    sb.writeln('· Key A 在卡片上设计上永远不可读，`??` 属正常现象。');
    return sb.toString();
  }

  static String dataSummary(MifareSector s) {
    final parts = <String>[];
    for (final b in s.dataBlocks) {
      parts.add('块${b.index}=${b.state.label}');
    }
    return parts.join(' ');
  }
}

String _hex2(int b) => b.toRadixString(16).padLeft(2, '0').toUpperCase();

String _bits(int v) {
  final sb = StringBuffer();
  for (var i = 3; i >= 0; i--) {
    sb.write((v >> i) & 1);
  }
  return sb.toString();
}

// --------------------------------------------------------------- 解析入口

class MifareParseException implements Exception {
  final String message;
  MifareParseException(this.message);
  @override
  String toString() => message;
}

/// 解析一个 MIFARE 转储文件
Future<MifareDump> parseMifareDump(String path) async {
  final file = File(path);
  if (!await file.exists()) {
    throw MifareParseException('文件不存在：$path');
  }
  final name = path.split(RegExp(r'[/\\]')).last;
  final bytes = await file.readAsBytes();
  final text = _decodeText(bytes);

  if (text != null && text.contains('Flipper NFC device')) {
    return _parseFlipper(name, text);
  }
  if (text != null && _looksLikeEml(text)) {
    return _parseEml(name, text);
  }
  return _parseRawBin(name, bytes);
}

String? _decodeText(List<int> bytes) {
  final head = bytes.length > 8192 ? bytes.sublist(0, 8192) : bytes;
  // 含大量控制字符说明是二进制而不是文本
  var ctrl = 0;
  for (final c in head) {
    if (c < 9 || (c > 13 && c < 32)) ctrl++;
  }
  if (ctrl > head.length ~/ 20) return null;
  return String.fromCharCodes(bytes);
}

bool _looksLikeEml(String text) {
  final lines = text
      .split(RegExp(r'\r?\n'))
      .where((l) => l.trim().isNotEmpty)
      .take(8)
      .toList();
  if (lines.length < 4) return false;
  final re = RegExp(r'^[0-9a-fA-F]{32}$');
  return lines.every((l) => re.hasMatch(l.trim()));
}

/// Flipper Zero 的文本转储
MifareDump _parseFlipper(String fileName, String text) {
  final notes = <String>[];
  var uid = <int>[];
  int? atqa;
  int? sak;
  var cardType = '1K';
  final blockMap = <int, MifareBlock>{};

  for (final raw in text.split(RegExp(r'\r?\n'))) {
    final line = raw.trim();
    if (line.isEmpty || line.startsWith('#')) continue;

    if (line.startsWith('UID:')) {
      uid = _parseHexList(line.substring(4));
    } else if (line.startsWith('ATQA:')) {
      final v = _parseHexList(line.substring(5));
      if (v.length >= 2) atqa = (v[0] << 8) | v[1];
    } else if (line.startsWith('SAK:')) {
      final v = _parseHexList(line.substring(4));
      if (v.isNotEmpty) sak = v[0];
    } else if (line.startsWith('Mifare Classic type:')) {
      cardType = line.substring('Mifare Classic type:'.length).trim();
    } else if (line.startsWith('Block ')) {
      final m = RegExp(r'^Block\s+(\d+):\s*(.*)$').firstMatch(line);
      if (m == null) continue;
      final idx = int.parse(m.group(1)!);
      final tokens = m.group(2)!.trim().split(RegExp(r'\s+'));
      if (tokens.length < 16) continue;

      final data = <int>[];
      final unknown = <bool>[];
      for (final t in tokens.take(16)) {
        if (t == '??' || t == '?') {
          data.add(0);
          unknown.add(true);
        } else {
          data.add(int.tryParse(t, radix: 16) ?? 0);
          unknown.add(false);
        }
      }
      blockMap[idx] =
          MifareBlock(idx, data, unknown.every((u) => u) ? null : unknown);
    }
  }

  if (blockMap.isEmpty) {
    throw MifareParseException('没有解析到任何 Block 行，可能不是 Flipper 转储。');
  }

  final maxIdx = blockMap.keys.reduce((a, b) => a > b ? a : b);
  final blocks = <MifareBlock>[];
  for (var i = 0; i <= maxIdx; i++) {
    blocks.add(blockMap[i] ?? MifareBlock(i, null));
  }

  final sectors = _buildSectors(blocks, notes);
  return MifareDump(
    fileName: fileName,
    format: MifareDumpFormat.flipperNfc,
    uid: uid,
    atqa: atqa,
    sak: sak,
    cardType: cardType,
    blocks: blocks,
    sectors: sectors,
    parseNotes: notes,
  );
}

int _sectorOfBlock(int block) {
  if (block < 128) return block ~/ 4;
  return 32 + (block - 128) ~/ 16;
}

int _trailerOf(int sector) =>
    sector < 32 ? sector * 4 + 3 : 128 + (sector - 32) * 16 + 15;

List<MifareSector> _buildSectors(List<MifareBlock> blocks, List<String> notes) {
  final bySector = <int, List<MifareBlock>>{};
  for (final b in blocks) {
    bySector.putIfAbsent(_sectorOfBlock(b.index), () => []).add(b);
  }
  final out = <MifareSector>[];
  final keys = bySector.keys.toList()..sort();
  for (final k in keys) {
    final bl = bySector[k]!;
    final trailerIdx = _trailerOf(k);
    MifareBlock? trailer;
    for (final b in bl) {
      if (b.index == trailerIdx) trailer = b;
    }
    out.add(MifareSector(k, bl, trailer));
    if (trailer == null || trailer.isFullyUnknown) {
      notes.add('扇区 $k 的尾块整块读不到，Key A / Key B / 访问位都不可用。');
    }
  }
  return out;
}

/// Proxmark / mfoc 的 .eml
MifareDump _parseEml(String fileName, String text) {
  final notes = <String>[];
  final blocks = <MifareBlock>[];
  for (final raw in text.split(RegExp(r'\r?\n'))) {
    final line = raw.replaceAll(RegExp(r'\s'), '');
    if (line.length < 32) continue;
    final bytes = <int>[];
    for (var i = 0; i + 1 < line.length && bytes.length < 16; i += 2) {
      bytes.add(int.tryParse(line.substring(i, i + 2), radix: 16) ?? 0);
    }
    if (bytes.length == 16) blocks.add(MifareBlock(blocks.length, bytes));
  }
  if (blocks.isEmpty) {
    throw MifareParseException('.eml 里没有解析到 16 字节的块。');
  }
  notes.add('这是纯数据转储：只有卡片内存内容。哪把密钥已知无法从文件本身判断，'
      '需要对照实体卡确认。');
  final sectors = _buildSectors(blocks, notes);
  final first = blocks.first.data;
  return MifareDump(
    fileName: fileName,
    format: MifareDumpFormat.proxmarkEml,
    uid: first != null ? first.sublist(0, 4) : <int>[],
    atqa: null,
    sak: null,
    cardType: blocks.length > 64 ? '4K' : '1K',
    blocks: blocks,
    sectors: sectors,
    parseNotes: notes,
  );
}

/// 裸 .bin / .mfd
MifareDump _parseRawBin(String fileName, List<int> bytes) {
  final notes = <String>[];
  if (bytes.length % 16 != 0) {
    throw MifareParseException(
        '长度不是 16 的整数倍（${bytes.length} 字节），不像 MIFARE 转储。');
  }
  final blocks = <MifareBlock>[];
  for (var i = 0; i + 16 <= bytes.length; i += 16) {
    blocks.add(MifareBlock(blocks.length, bytes.sublist(i, i + 16)));
  }
  if (blocks.isEmpty) {
    throw MifareParseException('文件是空的。');
  }
  notes.add('这是裸二进制转储：只有卡片内存内容，密钥可用性需要对照实体卡。');
  final sectors = _buildSectors(blocks, notes);
  final first = blocks.first.data;
  return MifareDump(
    fileName: fileName,
    format: MifareDumpFormat.rawBin,
    uid: first != null ? first.sublist(0, 4) : <int>[],
    atqa: null,
    sak: null,
    cardType: blocks.length > 64 ? '4K' : '1K',
    blocks: blocks,
    sectors: sectors,
    parseNotes: notes,
  );
}

List<int> _parseHexList(String s) {
  final out = <int>[];
  for (final tok in s.trim().split(RegExp(r'\s+'))) {
    if (tok.isEmpty) continue;
    final v = int.tryParse(tok, radix: 16);
    if (v != null) out.add(v & 0xFF);
  }
  return out;
}

/// 判断文件是否像 MIFARE 转储（供 FileIdentifier 使用）
Future<bool> looksLikeMifareDump(String path) async {
  final lower = path.toLowerCase();
  final file = File(path);
  if (!await file.exists()) return false;

  if (lower.endsWith('.nfc') || lower.endsWith('.shd')) {
    try {
      final bytes = await file.openRead(0, 512).fold<List<int>>(
          <int>[], (acc, chunk) => acc..addAll(chunk));
      final head = String.fromCharCodes(bytes);
      return head.contains('Flipper NFC device') || head.contains('Block 0:');
    } catch (_) {
      return false;
    }
  }
  if (lower.endsWith('.eml')) {
    try {
      final text = await file.readAsString();
      return _looksLikeEml(text);
    } catch (_) {
      return false;
    }
  }
  if (lower.endsWith('.mfd') || lower.endsWith('.bin')) {
    final len = await file.length();
    return len == 320 || len == 1024 || len == 4096;
  }
  return false;
}

/// 判断是否是 nonce 日志（mfkey32.log 等）
Future<bool> looksLikeNonceLog(String path) async {
  final lower = path.toLowerCase();
  if (lower.endsWith('.mfkey32.log') || lower.contains('mfkey32')) return true;
  if (lower.endsWith('.log')) {
    try {
      final text = await File(path).readAsString();
      final l = text.toLowerCase();
      return l.contains('nt0') || (l.contains('nt:') && l.contains('nr:'));
    } catch (_) {
      return false;
    }
  }
  return false;
}

/// Uint8List 便捷转换
Uint8List bytesOf(List<int> v) => Uint8List.fromList(v);
