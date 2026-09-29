// MIFARE 密钥候选生成与导出。
//
// 「密钥爆破」在离线下能做的事只有一件：把**候选钥匙表**准备好，交给真正
// 能和卡片交互的工具去试。原因很简单——转储里没有密文也没有 nonce，猜错了
// 没有任何东西能告诉你错了，所以「离线爆破」在物理上不成立。
//
// 但这条路依然非常有用，因为 MIFARE Classic 有一个致命弱点：只要知道同一张
// 卡上**任意一个**扇区的密钥，就能用 nested / hardnested 攻击在几秒内算出
// 其余所有密钥。实践中最常见的做法就是先撒一遍常见默认密钥，拿到一个突破点，
// 再放大到全卡。本文件负责把这两步的输入都准备好。

import 'dart:io';
import 'mifare.dart';

/// 一把候选钥匙及其来源
class MifareKeyCandidate {
  final String key; // 12 位大写十六进制
  final String source;

  const MifareKeyCandidate(this.key, this.source);
}

/// 常见公开默认密钥。
///
/// 这些是业界流传最广的出厂值 / 演示值 / 常见配置值。它们**不是**通用万能钥匙，
/// 只是「命中概率明显高于瞎猜」的一小张表，用来撞出第一个突破点。
const List<String> defaultMifareKeys = [
  'FFFFFFFFFFFF', // NXP 出厂默认
  '000000000000', // 全 0
  'A0A1A2A3A4A5', // NXP 演示 Key A
  'B0B1B2B3B4B5', // NXP 演示 Key B
  'D3F7D3F7D3F7', // NXP 演示
  'AABBCCDDEEFF', // 常见手工配置
  '123456789ABC', // 常见手工配置
  '010203040506', // 常见手工配置
  '001122334455', // 常见手工配置
  '66778899AABB', // 常见手工配置
  '4D3A99C351DD', // 常见公开默认
  '1A982C7E459A', // 常见公开默认
  '714C5C886E97', // 常见公开默认
  '587EE5F9350F', // 常见公开默认
  'A0478CC39091', // 常见公开默认
  '533CB6C723F6', // 常见公开默认
  '8FD0A4F256E9', // 常见公开默认
  '484558414354', // ASCII "HEXACT"
  'A0A1A2A3A4A5',
];

/// 把「转储里已经知道的钥匙」+「默认钥匙表」合并成候选表。
List<MifareKeyCandidate> buildKeyCandidates(MifareDump dump,
    {bool includeDefaults = true}) {
  final seen = <String>{};
  final out = <MifareKeyCandidate>[];

  for (final k in dump.knownKeys) {
    if (seen.add(k)) {
      final used = _sectorsUsing(dump, k);
      out.add(MifareKeyCandidate(k, '转储中已知（扇区 ${used.join('、')}）'));
    }
  }

  if (includeDefaults) {
    for (final k in defaultMifareKeys) {
      if (seen.add(k)) {
        out.add(MifareKeyCandidate(k, '常见默认密钥'));
      }
    }
  }
  return out;
}

List<int> _sectorsUsing(MifareDump dump, String hex) {
  final out = <int>[];
  for (final s in dump.sectors) {
    for (final k in [s.keyA, s.keyB]) {
      if (k == null) continue;
      if (k.map((b) => b.toRadixString(16).padLeft(2, '0')).join().toUpperCase() ==
          hex) {
        if (!out.contains(s.index)) out.add(s.index);
      }
    }
  }
  return out;
}

/// 生成 Proxmark3 / Flipper 通用的密钥字典内容（一行一把，12 位十六进制）。
///
/// 这个格式同时适用于：
///   · Proxmark3：`hf mf autopwn` 读取的 `mf_classic_dict.nfc`
///   · Flipper Zero：`/ext/nfc/assets/mf_classic_dict.nfc`
String buildKeysFile(List<MifareKeyCandidate> keys) {
  final sb = StringBuffer();
  sb.writeln('# MIFARE Classic 密钥字典（每行一把，12 位十六进制）');
  sb.writeln('# 生成自 HashCrack 的 MIFARE 转储分析器');
  sb.writeln('# 用法：Proxmark3 放到 mf_classic_dict.nfc；'
      'Flipper 放到 /ext/nfc/assets/mf_classic_dict.nfc');
  sb.writeln();
  for (final k in keys) {
    sb.writeln(k.key);
  }
  return sb.toString();
}

/// 带来源注释的可读版本，供人工核对
String buildKeysReadme(List<MifareKeyCandidate> keys) {
  final sb = StringBuffer();
  sb.writeln('密钥候选清单（共 ${keys.length} 把）');
  sb.writeln('=' * 40);
  for (final k in keys) {
    sb.writeln('${k.key}   <- ${k.source}');
  }
  return sb.toString();
}

/// 根据分析结果给出下一步操作建议（复制即可执行的命令）
String buildAdvice(MifareDump dump, {String dumpPath = ''}) {
  final unknown = dump.unknownKeySlots;
  final known = dump.knownKeys;
  final sb = StringBuffer();

  sb.writeln('下一步怎么做');
  sb.writeln('=' * 40);

  if (unknown.isEmpty) {
    sb.writeln('这张卡的全部扇区密钥都已经拿到，不需要再做任何恢复。');
    return sb.toString();
  }

  sb.writeln('还有 ${unknown.length} 处密钥未知：${unknown.join('、')}');
  sb.writeln();

  if (known.isEmpty) {
    sb.writeln('⚠ 转储里一把已知钥匙都没有，nested 攻击没有突破点。');
    sb.writeln('  先拿实体卡用下面的默认字典跑一遍，撞出第一个密钥后再继续。');
    sb.writeln();
  } else {
    sb.writeln('好消息：转储里已经有 ${known.length} 把已知钥匙。');
    sb.writeln('MIFARE Classic 只要知道任意一个扇区密钥，就能用 nested 攻击');
    sb.writeln('在几秒内把其余密钥全部算出来。所以走下面第 1 条路即可。');
    sb.writeln();
  }

  sb.writeln('【路线 1】实体卡 + nested 攻击（推荐，秒级）');
  sb.writeln('-' * 40);
  sb.writeln('Proxmark3：');
  sb.writeln('  1) 把 keys.txt 内容并入 mf_classic_dict.nfc');
  sb.writeln('  2) hf mf autopwn');
  sb.writeln('    （它会先用字典撞，撞到一把之后就自动 hardnested 展开全卡）');
  sb.writeln();
  sb.writeln('mfoc（需要一张能读的读卡器）：');
  sb.writeln('  mfoc -k ${known.isNotEmpty ? known.first : 'FFFFFFFFFFFF'} -O 全卡.mfd');
  sb.writeln();
  sb.writeln('【路线 2】Flipper Zero + mfkey32（不需要再跑字典）');
  sb.writeln('-' * 40);
  sb.writeln('  1) Flipper：NFC → 已保存 → 选择这张卡 → 「检测读卡器」');
  sb.writeln('  2) 拿着 Flipper 贴到目标读卡器上，让它多认证几次（收集 nonce）');
  sb.writeln('  3) 停止后 Flipper 会生成 mfkey32.log');
  sb.writeln('  4) 把该文件拖进本软件，用「导入 nonce 并恢复密钥」直接算出来');
  sb.writeln();
  sb.writeln('【路线 3】只读数据、不恢复密钥');
  sb.writeln('-' * 40);
  sb.writeln('  如果只是想把扇区数据读出来，可以用已知密钥逐扇区读；');
  sb.writeln('  但注意未知的那个密钥所在扇区读不到。');
  sb.writeln();
  if (dumpPath.isNotEmpty) {
    sb.writeln('当前转储：$dumpPath');
  }

  sb.writeln();
  sb.writeln('原理提醒');
  sb.writeln('-' * 40);
  sb.writeln('· 转储文件本身无法离线试密钥：里面只有认证后的明文，'
      '没有密文、没有 nonce，猜错也无从判断。');
  sb.writeln('· Key A 在卡片设计上就永远不可读，dump 里的 `??` 属正常现象。');
  sb.writeln('· 以上操作请只用于你自己拥有或已获授权的卡片。');
  return sb.toString();
}

/// 把一段文本写到指定文件，返回文件路径
Future<String> writeExport(String dir, String name, String content) async {
  final d = Directory(dir);
  if (!await d.exists()) {
    await d.create(recursive: true);
  }
  final f = File('$dir${Platform.pathSeparator}$name');
  await f.writeAsString(content);
  return f.path;
}
