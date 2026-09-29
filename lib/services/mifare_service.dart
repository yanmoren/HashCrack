// MIFARE 分析服务：解析转储、导出密钥候选、导入 nonce 日志并离线恢复密钥。

import 'dart:io';
import 'dart:isolate';

import '../models/mifare.dart';
import '../models/mifare_keys.dart';
import '../utils/crypto1.dart';

/// 一次 nonce 采集（两次认证会话），mfkey32 的最小输入单位。
class MifareNonceRecord {
  final int uid;
  final int nt0;
  final int nr0;
  final int ar0;
  final int nt1;
  final int nr1;
  final int ar1;

  /// 记录里带的话（如 `Sec 14 key A`），仅用于展示
  final String label;

  const MifareNonceRecord({
    required this.uid,
    required this.nt0,
    required this.nr0,
    required this.ar0,
    required this.nt1,
    required this.nr1,
    required this.ar1,
    this.label = '',
  });
}

/// 恢复结果
class MifareRecoveryResult {
  final List<MifareNonceRecord> records;
  final String? recoveredKey;
  final String? recoveredLabel;
  final int elapsedMs;
  final List<String> log;

  const MifareRecoveryResult({
    required this.records,
    required this.recoveredKey,
    required this.recoveredLabel,
    required this.elapsedMs,
    required this.log,
  });

  bool get success => recoveredKey != null;
}

/// 分析结果
class MifareAnalysisResult {
  final MifareDump dump;
  final String report;
  final String advice;
  final List<MifareKeyCandidate> candidates;

  const MifareAnalysisResult({
    required this.dump,
    required this.report,
    required this.advice,
    required this.candidates,
  });
}

class MifareService {
  const MifareService();

  /// 解析转储并生成报告
  Future<MifareAnalysisResult> analyze(String path) async {
    final dump = await parseMifareDump(path);
    return MifareAnalysisResult(
      dump: dump,
      report: dump.buildReport(),
      advice: buildAdvice(dump, dumpPath: path),
      candidates: buildKeyCandidates(dump),
    );
  }

  /// 导出密钥字典（Proxmark3 / Flipper 通用格式）与可读清单，返回两个路径
  Future<List<String>> exportKeys(
      String dir, MifareAnalysisResult result, String baseName) async {
    final keys = result.candidates;
    final dictPath = await writeExport(
        dir, '${baseName}_keys.txt', buildKeysFile(keys));
    final readmePath = await writeExport(
        dir, '${baseName}_keys_说明.txt', buildKeysReadme(keys));
    final reportPath =
        await writeExport(dir, '${baseName}_分析报告.txt', result.report);
    final advicePath =
        await writeExport(dir, '${baseName}_下一步.txt', result.advice);
    return [dictPath, readmePath, reportPath, advicePath];
  }

  /// 解析 nonce 日志（Flipper `mfkey32.log` / mfkey_extract 输出 / pm3 文本）
  Future<List<MifareNonceRecord>> parseNonceLog(String path) async {
    final f = File(path);
    if (!await f.exists()) {
      throw MifareParseException('文件不存在：$path');
    }
    final text = await f.readAsString();
    final records = parseNonceLogText(text);
    if (records.isEmpty) {
      throw MifareParseException(
          '没有从这个文件里找到成对的 nonce（需要 nt0/nr0/ar0 与 nt1/nr1/ar1）。\n'
          'Flipper 生成的 mfkey32.log，或 mfkey_extract 的输出都可以。');
    }
    return records;
  }

  /// 用 nonce 记录做 mfkey32 密钥恢复（放在独立 isolate 里跑，避免卡界面）
  Future<MifareRecoveryResult> recoverFromNonceLog(String path) async {
    final records = await parseNonceLog(path);
    final sw = Stopwatch()..start();
    final log = <String>[];
    log.add('解析到 ${records.length} 组 nonce。');

    for (var i = 0; i < records.length; i++) {
      final r = records[i];
      // LFSR 枚举 + 候选校验是纯计算，放到单独 isolate 里做
      final key = await Isolate.run(() => recoverMifareKeyFromNonces(
            uid: r.uid,
            nt0: r.nt0,
            nr0Enc: r.nr0,
            ar0Enc: r.ar0,
            nt1: r.nt1,
            nr1Enc: r.nr1,
            ar1Enc: r.ar1,
          ));
      sw.stop();
      if (key != null) {
        log.add('第 ${i + 1} 组算出密钥：${formatMifareKey(key)}');
        return MifareRecoveryResult(
          records: records,
          recoveredKey: formatMifareKey(key),
          recoveredLabel: r.label,
          elapsedMs: sw.elapsedMilliseconds,
          log: log,
        );
      }
      log.add('第 ${i + 1} 组未命中（数据可能不完整或不是同一次认证）。');
    }
    sw.stop();
    return MifareRecoveryResult(
      records: records,
      recoveredKey: null,
      recoveredLabel: null,
      elapsedMs: sw.elapsedMilliseconds,
      log: log,
    );
  }
}

/// 从任意文本里抽取 nonce 记录。
///
/// 取向是「尽量容忍各家格式」，因为 Flipper 固件版本之间、mfkey_extract 与
/// Proxmark3 的输出写法都不一样。策略是按标签取值，标签大小写不敏感，
/// 后缀 `0`/`1` 区分两次会话；`nt`/`nr`/`ar` 不带后缀时按第一组处理。
/// 每组 nonce 以出现 `nt*` 为起点，`uid|cuid` 对后续所有组生效。
List<MifareNonceRecord> parseNonceLogText(String text) {
  final tokenRe = RegExp(
      r'(uid|cuid|nt1|nr1|ar1|nt0|nr0|ar0|nt|nr|ar)\s*[:=]?\s*(0x[0-9a-fA-F]{1,8}|[0-9a-fA-F]{8})\b',
      caseSensitive: false);

  final out = <MifareNonceRecord>[];
  int? uid;
  int? nt0, nr0, ar0, nt1, nr1, ar1;
  var label = '';

  void flush() {
    if (uid != null &&
        nt0 != null &&
        nr0 != null &&
        ar0 != null &&
        nt1 != null &&
        nr1 != null &&
        ar1 != null) {
      out.add(MifareNonceRecord(
        uid: uid,
        nt0: nt0!,
        nr0: nr0!,
        ar0: ar0!,
        nt1: nt1!,
        nr1: nr1!,
        ar1: ar1!,
        label: label,
      ));
    }
    nt0 = nr0 = ar0 = nt1 = nr1 = ar1 = null;
    // 说明文字属于「一组记录」，结算完要清掉，否则会污染下一组的标签。
    label = '';
  }

  for (final m in tokenRe.allMatches(text)) {
    final labelRaw = m.group(1)!.toLowerCase();
    final v = _parseHex32(m.group(2)!);
    if (v == null) continue;

    // 取这一行里 token 之前的文字（如 "Sec 14 key A"），当成本组记录的说明。
    // Flipper 的写法是 `Sec 14 key A cuid 2A234F80`，说明文字挂在 uid 前面，
    // 所以 uid/cuid 也要取一次，不能只认 nt0 那一行。
    final lineStart = text.lastIndexOf('\n', m.start);
    final ctx = text
        .substring(lineStart + 1, m.start)
        .trim()
        .replaceAll(RegExp(r'\s+'), ' ');

    switch (labelRaw) {
      case 'uid':
      case 'cuid':
        uid = v;
        if (ctx.isNotEmpty) label = ctx;
        break;
      case 'nt':
      case 'nt0':
        if (nt0 != null) flush(); // 出现新的第一组，先结算上一组
        nt0 = v;
        if (label.isEmpty && ctx.isNotEmpty) label = ctx;
        break;
      case 'nr':
      case 'nr0':
        nr0 = v;
        break;
      case 'ar':
      case 'ar0':
        ar0 = v;
        break;
      case 'nt1':
        nt1 = v;
        break;
      case 'nr1':
        nr1 = v;
        break;
      case 'ar1':
        ar1 = v;
        flush(); // 第二组收齐即结算
        break;
    }
  }
  flush();
  return out;
}

int? _parseHex32(String s) {
  final t = s.toLowerCase().startsWith('0x') ? s.substring(2) : s;
  if (t.length > 8) return null;
  return int.tryParse(t, radix: 16);
}
