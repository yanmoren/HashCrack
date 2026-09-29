import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:path/path.dart' as p;
import '../models/brute_force.dart';
import '../utils/constants.dart';
import 'app_paths.dart';

class HashcatProgress {
  final double progress;
  final int speedKhs;
  final int etaSeconds;
  final int testedCount;
  final int totalCount;
  final HashcatStatus status;
  final bool cracked;

  const HashcatProgress({
    this.progress = 0,
    this.speedKhs = 0,
    this.etaSeconds = 0,
    this.testedCount = 0,
    this.totalCount = 0,
    this.status = HashcatStatus.idle,
    this.cracked = false,
  });
}

/// 从 hashcat 的字符流里抠出状态 JSON 对象。
///
/// 为什么需要它：hashcat 7.x 用 --status-json 输出的是**单行** JSON，但在
/// 非交互模式下它前面会拼上「[s]tatus [p]ause [b]ypass ... =>」这个交互式
/// 提示符（还有一串空格填充）。按 \n 切行后，这一行是以前缀开头而不是 '{'，
/// 用 `line.startsWith('{')` 判断会 100% 漏掉，进度回调永远不会触发。
/// 这里改用大括号平衡扫描，从任意位置把 JSON 抠出来，并正确处理字符串
/// 字面量内部的括号与转义（哈希值里经常出现这类字符）。
class StatusJsonExtractor {
  final StringBuffer _buf = StringBuffer();
  int _depth = 0;
  bool _inString = false;
  bool _escaped = false;

  /// 每抠出一个完整 JSON 对象就回调一次
  final void Function(Map<String, dynamic> json)? onObject;

  StatusJsonExtractor({this.onObject});

  void reset() {
    _buf.clear();
    _depth = 0;
    _inString = false;
    _escaped = false;
  }

  void feed(String text) {
    for (var i = 0; i < text.length; i++) {
      final c = text[i];

      if (_depth == 0) {
        if (c == '{') {
          _depth = 1;
          _inString = false;
          _escaped = false;
          _buf.write(c);
        }
        continue;
      }

      _buf.write(c);

      if (_inString) {
        if (_escaped) {
          _escaped = false;
        } else if (c == '\\') {
          _escaped = true;
        } else if (c == '"') {
          _inString = false;
        }
        continue;
      }

      if (c == '"') {
        _inString = true;
      } else if (c == '{') {
        _depth++;
      } else if (c == '}') {
        _depth--;
        if (_depth == 0) {
          final obj = _buf.toString();
          _buf.clear();
          _emit(obj);
        }
      }
    }
  }

  void _emit(String text) {
    try {
      final decoded = jsonDecode(text);
      if (decoded is Map<String, dynamic>) onObject?.call(decoded);
    } catch (_) {
      // 个别片段可能不是合法 JSON，忽略即可，不影响后续解析
    }
  }
}

/// 当前攻击阶段，用于在界面上区分「字典 2/5」和「掩码 ?d?d?d?d」。
/// 之前只有阶段枚举、没有明细，导致掩码攻击跑很久时界面仍显示「字典攻击」，
/// 用户会误以为卡死。
class HashcatPhase {
  /// true = 掩码攻击，false = 字典攻击
  final bool isMask;

  /// true = 用户手动发起的暴力破解（字符集 + 长度递增）。
  /// 与掩码攻击区分开是因为暴力破解可能「不限时」地跑很久，
  /// 界面上需要明确告知用户这是他自己选的策略，而不是软件卡住了。
  final bool isBruteForce;

  /// 明细文案，例如「字典 1/3」或「掩码 ?d?d?d?d」
  final String detail;

  const HashcatPhase({
    required this.isMask,
    required this.detail,
    this.isBruteForce = false,
  });
}

enum HashcatStatus {
  idle(0, '空闲'),
  running(1, '运行中'),
  paused(2, '已暂停'),
  cracked(3, '已破解'),
  exhausted(4, '已耗尽'),
  quit(5, '已退出');

  const HashcatStatus(this.code, this.label);
  final int code;
  final String label;

  static HashcatStatus fromCode(int code) {
    return HashcatStatus.values.firstWhere((e) => e.code == code, orElse: () => HashcatStatus.idle);
  }
}

class HashcatResult {
  final bool cracked;
  final String password;
  final String log;
  final String error;
  const HashcatResult({
    this.cracked = false,
    this.password = '',
    this.log = '',
    this.error = '',
  });
}

class HashcatService {
  final String hashcatPath;
  final String workDir;

  /// 内置便携 Python（runtime\python\python.exe）。用于校验 ZIP 候选密码，
  /// 不依赖目标机器安装 Python。为空则跳过校验。
  final String pythonPath;

  final void Function(HashcatProgress p)? onProgress;
  final void Function(String line)? onLog;

  /// 攻击阶段变化回调（字典 / 掩码切换时触发）
  final void Function(HashcatPhase phase)? onPhase;

  Process? _process;
  bool _cancelled = false;
  String _initError = '';
  String? _hashFormatError;
  String? _envError;

  /// 状态 JSON 提取器（详见 StatusJsonExtractor 的说明）
  late final StatusJsonExtractor _jsonExtractor =
      StatusJsonExtractor(onObject: _parseStatusObject);

  /// 本次任务的原始文件与哈希模式，供候选密码校验使用
  String _sourceFile = '';
  int _hashType = 0;

  /// 单个字典的最长运行时间（秒）。0 = 不限时。超大字典不至于让界面看起来卡死。
  final int dictRuntimeLimitSec;

  /// 单组掩码的最长运行时间（秒）。0 = 不限时。
  ///
  /// 原来是写死的 180 秒，这是个真实的坑：WPA 握手包（-m 22000）在普通机器上
  /// 只有几万 H/s，3 分钟连 8 位数字的零头都跑不完，于是每一组掩码都被截断，
  /// 界面上就出现「所有策略均未命中」——其实根本没跑完，只是被时间砍了。
  /// 现在改为可配置，并且阶段明细里会给出组合空间与预计耗时。
  final int maskRuntimeLimitSec;

  /// 最近一次攻击实测到的速度（次/秒）。
  /// 用作暴力破解面板里「预计耗时」的输入——没有实测速度就只能显示「—」，
  /// 不能凭空猜一个数字误导用户决策。
  int _lastSpeedPerSec = 0;

  /// 最近一次状态上报里的候选进度。
  /// 用来区分「整个空间都跑完了」和「被限时截断了」——这两件事对用户
  /// 意味着完全不同的下一步：前者该换字符集，后者只是没跑完。
  int _lastTestedCount = 0;
  int _lastTotalCount = 0;

  /// 上一次暴力破解是否因为限时被截断。
  bool _lastBruteForceTruncated = false;

  int get lastSpeedPerSec => _lastSpeedPerSec;

  /// 上一次运行遇到的环境问题（如缺少 OpenCL 运行库），供 UI 展示中文指引
  String? get lastEnvError => _envError;

  /// ZipCrypto 系列模式：密码校验只有 2 字节，误报率约 1/4096。
  /// 这些模式必须跑完整个字典（--keep-guessing）收集全部候选，再逐个验证，
  /// 否则用大字典时几乎必然返回一个假密码。
  static const Set<int> _multiCandidateModes = {17210, 17220, 17225, 17230};

  HashcatService({
    required this.hashcatPath,
    required this.workDir,
    this.pythonPath = '',
    this.onProgress,
    this.onLog,
    this.onPhase,
    this.dictRuntimeLimitSec = 900,
    this.maskRuntimeLimitSec = 180,
  }) {
    if (hashcatPath.isEmpty || !File(hashcatPath).existsSync()) {
      _initError = 'hashcat 未找到: ${hashcatPath.isEmpty ? "(路径为空)" : hashcatPath}\n'
          '请安装 hashcat 或在设置中指定正确路径。\n'
          '下载地址: https://hashcat.net/hashcat/';
    }
  }

  void cancel() {
    _cancelled = true;
    _process?.kill(ProcessSignal.sigterm);
  }

  Future<HashcatResult> run({
    required String hash,
    required int hashType,
    required List<String> dicts,
    List<String> masks = const [],

    /// 候选哈希模式（按常见程度排序）。
    ///
    /// 有些哈希结构上同时符合多个模式——32 位十六进制既可能是 MD5，也可能是
    /// NTLM 或 MD4，hashcat 的 `--identify` 会把这几个都列出来而拒绝替我们选。
    /// 字典阶段很便宜，所以这里对每个候选模式各跑一遍字典，命中率比只赌一个
    /// 高得多；掩码与暴力破解仍然只用首选模式，避免耗时被放大数倍。
    List<int> hashTypes = const [],

    /// 可选的暴力破解阶段（排在字典与掩码之后）。
    /// 自动流程不传，只有用户显式指定暴力破解时才会带上。
    BruteForceConfig? bruteForce,
    String sessionName = 'session',

    /// 原始加密文件路径。ZIP 类哈希破解后需要拿它来校验候选密码，
    /// 留空则跳过校验（结果可能是假密码）。
    String sourceFile = '',
  }) async {
    final ctx = await _prepareRun(
      hash: hash,
      hashType: hashType,
      sessionName: sessionName,
      sourceFile: sourceFile,
    );
    if (ctx.early != null) return ctx.early!;
    final logBuffer = ctx.log;

    // Dictionary attack
    final modes = hashTypes.isEmpty ? <int>[hashType] : hashTypes;
    var lastFormatError = '';
    for (var i = 0; i < modes.length; i++) {
      final mode = modes[i];
      if (_cancelled) break;
      if (modes.length > 1) {
        _log(logBuffer,
            '== 按候选模式 -m $mode 尝试（${i + 1}/${modes.length}）==');
      }
      final dictAttackResult = await _runDictionaryAttack(
          ctx.hashFile, mode, dicts, ctx.outFile, ctx.potFile, sessionName, logBuffer);
      if (dictAttackResult.cracked) return dictAttackResult;
      if (dictAttackResult.error.isNotEmpty) {
        // 「这个模式与该哈希格式不符」是候选模式里再正常不过的情况
        // （猜错的那几个必然报错），不能因为一次不匹配就整体放弃。
        final isFormatError = dictAttackResult.error.startsWith('哈希格式错误');
        if (isFormatError && modes.length > 1) {
          lastFormatError = dictAttackResult.error;
          _log(logBuffer, '-m $mode 与该哈希格式不符，继续试下一个候选');
          continue;
        }
        return dictAttackResult;
      }
    }
    if (lastFormatError.isNotEmpty && modes.length > 1) {
      return HashcatResult(
        cracked: false,
        password: '',
        log: logBuffer.toString(),
        error: '这段哈希与全部候选模式都不匹配（${modes.join('、')}）：\n'
            '$lastFormatError\n\n'
            '请确认拷贝完整、没有多余的换行或前后缀。',
      );
    }

    // Mask attack
    final maskAttackResult = await _runMaskAttack(ctx.hashFile, hashType, masks, ctx.outFile, ctx.potFile, sessionName, logBuffer);
    if (maskAttackResult.cracked || maskAttackResult.error.isNotEmpty || _cancelled) {
      return maskAttackResult;
    }

    // 暴力破解（仅在调用方显式指定时执行）
    if (bruteForce != null) {
      final bfResult = await _runBruteForce(ctx.hashFile, hashType, bruteForce,
          ctx.outFile, ctx.potFile, sessionName, logBuffer);
      if (bfResult.cracked || bfResult.error.isNotEmpty || _cancelled) {
        return bfResult;
      }
    }

    return HashcatResult(
      cracked: false,
      password: '',
      log: logBuffer.toString(),
      error: _cancelled
          ? '已取消'
          : '所有策略均未命中。\n\n'
              '已尝试：${dicts.length} 个字典 + ${(masks.isEmpty ? _defaultMasks() : masks).length} 组掩码'
              '${bruteForce == null ? '' : ' + 暴力破解（${bruteForce.label}）'}。\n'
              '建议：换一个更大的字典（设置 → 添加用户字典），\n'
              '或用「暴力破解」按字符集和长度自行穷举（界面上会先给出预计耗时）。',
    );
  }

  /// 只跑暴力破解，跳过字典与掩码。
  ///
  /// 用于「所有策略均未命中」之后，用户手动指定字符集与长度再试一次。
  /// 复用已提取的哈希，因此不需要重新解析源文件。
  Future<HashcatResult> runBruteForce({
    required String hash,
    required int hashType,
    required BruteForceConfig config,
    String sessionName = 'bruteforce',
    String sourceFile = '',
  }) async {
    final ctx = await _prepareRun(
      hash: hash,
      hashType: hashType,
      sessionName: sessionName,
      sourceFile: sourceFile,
    );
    if (ctx.early != null) return ctx.early!;
    final logBuffer = ctx.log;

    final r = await _runBruteForce(ctx.hashFile, hashType, config,
        ctx.outFile, ctx.potFile, sessionName, logBuffer);
    if (r.cracked || r.error.isNotEmpty) return r;

    // 结论文案必须区分「跑完了」和「限时被截断」，否则用户会以为
    // 这个字符集+长度已经被证明无效，从而错过真正的密码。
    final String reason;
    if (_cancelled) {
      reason = '已取消';
    } else if (_lastBruteForceTruncated) {
      reason = '暴力破解未命中（限时 ${config.runtimeSec} 秒已用满，组合空间未跑完）。\n\n'
          '「${config.label}」共 ${formatKeyspace(config.keyspace)} 种组合，'
          '这次只跑了其中一部分。\n'
          '要继续的话：把运行方式改成「不限时」让它自己跑完，'
          '或者缩小字符集与长度范围。';
    } else {
      reason = '暴力破解未命中。\n\n'
          '已遍历「${config.label}」全部 ${formatKeyspace(config.keyspace)} 种组合均已试过，'
          '这个范围内确实没有正确密码。\n'
          '可以放宽字符集（例如加入字母）或提高最大长度后重试——'
          '界面上会先算出新的组合空间与预计耗时。';
    }

    return HashcatResult(
      cracked: false,
      password: '',
      log: logBuffer.toString(),
      error: reason,
    );
  }

  /// 每轮攻击共用的准备工作：建临时文件、写哈希、查历史记录。
  ///
  /// 返回的 [early] 非空时表示无需继续（初始化失败 / 落盘失败 / potfile 已命中）。
  Future<_RunContext> _prepareRun({
    required String hash,
    required int hashType,
    required String sessionName,
    required String sourceFile,
  }) async {
    _sourceFile = sourceFile;
    _hashType = hashType;
    final ctx = _RunContext(
      hashFile: p.join(Directory.systemTemp.absolute.path, '${sessionName}_hash.txt'),
      outFile: p.join(Directory.systemTemp.absolute.path, '${sessionName}_out.txt'),
      potFile: p.join(Directory.systemTemp.absolute.path, '${sessionName}.potfile'),
    );
    _cancelled = false;
    _hashFormatError = null;
    _lastSpeedPerSec = 0;
    _lastTestedCount = 0;
    _lastTotalCount = 0;
    _lastBruteForceTruncated = false;

    if (_initError.isNotEmpty) {
      ctx.early = HashcatResult(
          cracked: false, password: '', log: '', error: _initError);
      return ctx;
    }

    try {
      await File(ctx.hashFile).writeAsString('$hash\n');
    } catch (e) {
      ctx.early = HashcatResult(
          cracked: false, password: '', log: '', error: '无法写入哈希文件: $e');
      return ctx;
    }
    try {
      await File(ctx.outFile).writeAsString('');
    } catch (e) {
      ctx.early = HashcatResult(
          cracked: false, password: '', log: '', error: '无法创建输出文件: $e');
      return ctx;
    }
    _log(ctx.log, '哈希文件: ${ctx.hashFile}');
    _log(ctx.log, 'hashcat 路径: $hashcatPath');
    _log(ctx.log,
        '哈希类型: $hashType, 哈希值: ${hash.substring(0, hash.length > 60 ? 60 : hash.length)}...');

    // 先查 potfile：同一个文件破解第二次时，hashcat 会因为「哈希已在 potfile 中」
    // 而直接跳过、不写 outfile，导致明明有结果却报失败。
    final cached =
        await _lookupPotfile(ctx.hashFile, hashType, ctx.potFile, ctx.log);
    if (cached.isNotEmpty) {
      // potfile 里可能存着多个候选（弱校验模式会记录全部命中），
      // 不能无脑取第一个，必须走同一套验证流程。
      final pw = await _resolvePassword(cached, ctx.log);
      if (pw != null) {
        _log(ctx.log, '命中历史破解记录（potfile）');
        ctx.early = HashcatResult(
            cracked: true, password: pw, log: ctx.log.toString());
      }
    }
    return ctx;
  }

  /// 用 hashcat --show 从 potfile 里取出已记录的候选密码（可能有多个）。
  Future<List<String>> _lookupPotfile(
      String hashFile, int hashType, String potFile, StringBuffer log) async {
    try {
      if (!await File(potFile).exists()) return const [];
      final r = await Process.run(
        hashcatPath,
        ['-m', '$hashType', '--show', hashFile, '--potfile-path', potFile],
        workingDirectory: File(hashcatPath).parent.path,
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
      ).timeout(const Duration(seconds: 60));
      final out = (r.stdout as String?) ?? '';
      final list = <String>[];
      for (final line in out.split('\n')) {
        final t = line.trim();
        if (t.isEmpty) continue;
        final idx = t.lastIndexOf(':');
        final cand = (idx > 0 && idx < t.length - 1) ? t.substring(idx + 1) : t;
        if (!list.contains(cand)) list.add(cand);
      }
      return list;
    } catch (e) {
      _log(log, 'potfile 查询失败: $e');
    }
    return const [];
  }

  /// 从候选密码里挑出真正可用的那一个：
  /// - 0 个       → 没破解
  /// - 1 个       → 直接用
  /// - 多个       → 逐个验证，取真能解开的；验证不了就退回第一个
  Future<String?> _resolvePassword(
      List<String> candidates, StringBuffer log) async {
    if (candidates.isEmpty) return null;
    if (candidates.length == 1) return candidates.first;

    _log(log, 'hashcat 命中 ${candidates.length} 个候选，正在逐个验证真伪...');
    final verified = await _verifyCandidates(candidates);
    if (verified != null && verified.isNotEmpty) {
      _log(log, '验证通过: $verified');
      return verified;
    }
    _log(log,
        '未能完成验证，返回首个候选（另有 ${candidates.length - 1} 个候选可能不匹配）');
    return candidates.first;
  }

  Future<HashcatResult> _runDictionaryAttack(
      String hashFile,
      int hashType,
      List<String> dicts,
      String outFile,
      String potFile,
      String sessionName,
      StringBuffer logBuffer) async {
    if (dicts.isEmpty) {
      return HashcatResult(
          cracked: false, password: '', log: logBuffer.toString(),
          error: '没有可用的字典文件。请在设置中添加字典。');
    }

    var done = 0;
    for (final dict in dicts) {
      if (_cancelled) break;
      if (!await File(dict).exists()) {
        _log(logBuffer, '跳过不存在的字典: $dict');
        continue;
      }
      done++;
      final name = dict.split(RegExp(r'[/\\]')).last;
      onPhase?.call(HashcatPhase(
        isMask: false,
        detail: '字典 $done/${dicts.length}：$name',
      ));
      _log(logBuffer, '== 字典攻击 ($done/${dicts.length}): $dict ==');
      final args = <String>[
        '-m', '$hashType', '-a', '0', hashFile, dict,
        '--status', '--status-timer=2', '-o', outFile,
        '--potfile-path', potFile, '--session', sessionName,
        '--status-json',
      ];
      if (dictRuntimeLimitSec > 0) {
        args.add('--runtime=$dictRuntimeLimitSec');
      }
      final r = await _runHashcat(
        args,
        outFile,
        logBuffer,
        // 不限时的字典攻击必须解除 30 分钟的进程硬超时，
        // 否则大字典跑到一半会被上层强行杀掉。取消按钮仍然可用。
        hardTimeout: dictRuntimeLimitSec > 0
            ? AppConstants.hashcatRunTimeout
            : null,
      );
      if (r.cracked) {
        return HashcatResult(
            cracked: true,
            password: r.password,
            log: logBuffer.toString());
      }
      if (r.error.isNotEmpty) {
        return HashcatResult(
            cracked: false,
            password: '',
            log: logBuffer.toString(),
            error: '哈希格式错误: ${r.error}');
      }
      if (_cancelled) break;
    }
    return const HashcatResult(cracked: false, password: '');
  }

  Future<HashcatResult> _runMaskAttack(
      String hashFile,
      int hashType,
      List<String> masks,
      String outFile,
      String potFile,
      String sessionName,
      StringBuffer logBuffer) async {
      if (!_cancelled) {
      final autoMasks = masks.isEmpty ? _defaultMasks() : masks;
      final total = autoMasks.length;
      for (var mi = 0; mi < total; mi++) {
        final mask = autoMasks[mi];
        if (_cancelled) break;
        // 把组合空间和预计耗时直接写进阶段明细：掩码攻击最容易让人误会
        // 「软件卡死」，必须让用户看到还剩多少、大概要多久。
        final ks = maskKeyspace(mask);
        final eta = _lastSpeedPerSec > 0 ? _etaFor(ks) : null;
        final detail = StringBuffer('掩码 ${mi + 1}/$total：$mask');
        if (ks > BigInt.zero) {
          detail.write('（${formatKeyspace(ks)} 种组合');
          if (eta != null) detail.write('，预计 ${formatSeconds(eta)}');
          detail.write('）');
        }
        onPhase?.call(HashcatPhase(isMask: true, detail: detail.toString()));
        _log(logBuffer, '== 掩码攻击 (${mi + 1}/$total, $mask) ==');
        if (ks > BigInt.zero) {
          _log(logBuffer,
              '   组合空间 ${formatKeyspace(ks)}${eta == null ? '' : '，预计 ${formatSeconds(eta)}'}'
              '${maskRuntimeLimitSec > 0 ? '，单步限时 $maskRuntimeLimitSec 秒' : '，不限时'}');
        }
        final args = <String>[
          '-m', '$hashType', '-a', '3', hashFile, mask,
          '--status', '--status-timer=2', '-o', outFile,
          '--potfile-path', potFile, '--session', '${sessionName}_m$mi',
          '--status-json',
        ];
        if (maskRuntimeLimitSec > 0) {
          args.add('--runtime=$maskRuntimeLimitSec');
        }
        final r = await _runHashcat(
          args,
          outFile,
          logBuffer,
          hardTimeout:
              maskRuntimeLimitSec > 0 ? AppConstants.hashcatRunTimeout : null,
        );
        if (r.cracked) {
          return HashcatResult(
              cracked: true,
              password: r.password,
              log: logBuffer.toString());
        }
        if (r.error.isNotEmpty) {
          return HashcatResult(
              cracked: false,
              password: '',
              log: logBuffer.toString(),
              error: '哈希格式错误: ${r.error}');
        }
        if (_cancelled) break;
      }
    }
    return const HashcatResult(cracked: false, password: '');
  }

  /// 按组合空间与实测速度估算耗时，返回**秒数**。
  ///
  /// 返回 BigInt 而非 Duration：`Duration` 内部是 int64 微秒，上限约
  /// 9.22e12 秒（≈29.2 万年），超过会静默回绕成负数，把超长耗时说成
  /// 「不到 1 秒」。暴力破解的空间轻易就越过这条线，必须用大整数。
  BigInt? _etaFor(BigInt ks) {
    if (_lastSpeedPerSec <= 0 || ks <= BigInt.zero) return null;
    return ks ~/ BigInt.from(_lastSpeedPerSec);
  }

  /// 暴力破解：`-a 3 -1 <字符集> ?1?1…?1 --increment`。
  ///
  /// 用 `--increment` 而不是为每个长度单独起一次进程，有两个好处：
  /// 1. 长度由短到长连续推进（短密码命中概率更高，能更早出结果）；
  /// 2. 省掉反复启动进程、编译/加载内核的开销，慢哈希上这个开销很可观。
  Future<HashcatResult> _runBruteForce(
      String hashFile,
      int hashType,
      BruteForceConfig config,
      String outFile,
      String potFile,
      String sessionName,
      StringBuffer logBuffer) async {
    if (_cancelled) return const HashcatResult(cracked: false, password: '');

    final ks = config.keyspace;
    final eta = _etaFor(ks);
    final unlimited = config.runtimeSec <= 0;

    final detail = StringBuffer('暴力破解：${config.label}');
    if (ks > BigInt.zero) {
      detail.write('（${formatKeyspace(ks)} 种组合');
      if (eta != null) detail.write('，预计 ${formatSeconds(eta)}');
      detail.write('）');
    }
    onPhase?.call(HashcatPhase(
      isMask: true,
      isBruteForce: true,
      detail: detail.toString(),
    ));

    _log(logBuffer, '== 暴力破解 ==');
    _log(logBuffer, '字符集: ${config.charset.label}（${config.charset.sample}，'
        '每位置 ${config.charset.size} 种）');
    _log(logBuffer, '长度: ${config.minLen} ~ ${config.maxLen} 位');
    _log(logBuffer, '组合空间: ${formatKeyspace(ks)}');
    _log(logBuffer, '预计耗时: ${eta == null ? '未知（以实测速度为准）' : formatSeconds(eta)}');
    _log(logBuffer, '运行时限: ${unlimited ? '不限时（可随时取消）' : '${config.runtimeSec} 秒'}');

    final args = <String>[
      '-m', '$hashType',
      '-a', '3',
      // 位置参数顺序必须是「哈希文件 掩码」。写反了 hashcat 会把哈希文件
      // 当成掩码文件，直接报错退出（Using --custom-charsetX with mask files
      // is misleading），而且因为对用户来说只是「没反应」，很难排查。
      hashFile,
      config.mask,
      ...config.optionArgs,
      '--status', '--status-timer=2', '-o', outFile,
      '--potfile-path', potFile, '--session', '${sessionName}_bf',
      '--status-json',
    ];
    if (!unlimited) args.add('--runtime=${config.runtimeSec}');

    final r = await _runHashcat(
      args,
      outFile,
      logBuffer,
      hardTimeout: unlimited ? null : AppConstants.hashcatRunTimeout,
    );

    if (r.cracked) {
      return HashcatResult(
          cracked: true, password: r.password, log: logBuffer.toString());
    }
    if (r.error.isNotEmpty) {
      return HashcatResult(
          cracked: false,
          password: '',
          log: logBuffer.toString(),
          error: '哈希格式错误: ${r.error}');
    }

    // 判定这次是「跑完了整个空间」还是「限时到点被砍掉」。
    // 仅在限时模式下才可能是截断，不限时一定是自然结束。
    _lastBruteForceTruncated = !unlimited &&
        _lastTotalCount > 0 &&
        _lastTestedCount < _lastTotalCount;
    if (_lastBruteForceTruncated) {
      _log(logBuffer,
          '限时 ${config.runtimeSec} 秒已到，hashcat 被中止（组合空间未跑完）');
    }
    return const HashcatResult(cracked: false, password: '');
  }

  Future<_RunResult> _runHashcat(
      List<String> args, String outFile, StringBuffer log,
      {Duration? hardTimeout = AppConstants.hashcatRunTimeout}) async {
    // 注意：不要写死 --backend-devices。不同电脑的设备编号不一样，
    // 钉死设备号会导致换机后选错设备甚至无法启动，交由 hashcat 自动挑选。
    final fullArgs = [...args, '--force'];

    // ZipCrypto 这类弱校验模式必须跑完整个字典收齐候选，否则大字典下
    // 命中第一个（几乎必是误报）就停，会返回一个假密码。
    if (_multiCandidateModes.contains(_hashType)) {
      fullArgs.add('--keep-guessing');
    }
    _log(log, '> ${hashcatPath} ${fullArgs.join(' ')}');

    String? workingDir = workDir;
    try {
      final hashcatDir = File(hashcatPath).parent.path;
      if (hashcatDir.isNotEmpty) {
        workingDir = hashcatDir;
      }
    } catch (_) {}

    try {
      _process = await Process.start(hashcatPath, fullArgs,
          workingDirectory: workingDir);
    } catch (e) {
      _log(log, '启动 hashcat 失败: $e');
      return _RunResult(false, '');
    }

    // 不能用 LineSplitter：hashcat 在非交互模式下用 \r 做进度覆盖，
    // 而且状态 JSON 会被「[s]tatus [p]ause ... =>」提示符粘在同一行，
    // 按 \n 切分后行首永远不是 '{'，旧实现因此从未解析到过进度。
    // 这里直接消费原始字符流：先喂给 JSON 提取器，再按 \r/\n 切成日志行。
    final stdoutSub = _process!.stdout
        .transform(utf8.decoder)
        .listen((chunk) => _feedChunk(chunk, log, stderr: false));
    final stderrSub = _process!.stderr
        .transform(utf8.decoder)
        .listen((chunk) => _feedChunk(chunk, log, stderr: true));

    // 等待进程结束。hardTimeout 为 null 表示不限时——暴力破解
    // （尤其是 WPA 这类慢哈希）本来就可能要跑几个小时甚至更久，
    // 用固定 30 分钟杀掉它会直接毁掉用户主动发起的长时间任务。
    // 不限时并不意味着不可控：取消按钮随时可以终止进程。
    int exitCode = -1;
    try {
      if (hardTimeout == null) {
        exitCode = await _process!.exitCode;
      } else {
        exitCode = await _process!.exitCode.timeout(
          hardTimeout,
          onTimeout: () {
            _log(log, 'hashcat 超时，正在终止...');
            _process?.kill(ProcessSignal.sigkill);
            return -999;
          },
        );
      }
    } catch (e) {
      _log(log, 'hashcat 进程异常: $e');
    }
    await stdoutSub.cancel();
    await stderrSub.cancel();
    _process = null;
    _resetJsonState();

    if (_hashFormatError != null) {
      _log(log, '哈希格式错误: $_hashFormatError');
      return _RunResult(false, '', _hashFormatError!);
    }

    final password = await _readOutputWithNote(outFile, log);
    if (password.isNotEmpty) {
      _log(log, '破解成功: $password');
      return _RunResult(true, password);
    }
    if (exitCode != 0 && exitCode != 1 && exitCode != -999) {
      _log(log, 'hashcat 退出码: $exitCode');
    }
    return _RunResult(false, '');
  }

  void _resetJsonState() => _jsonExtractor.reset();

  /// 消费一段 hashcat 输出：先尝试从中抠出状态 JSON，再切成可读的日志行。
  void _feedChunk(String chunk, StringBuffer log, {required bool stderr}) {
    _jsonExtractor.feed(chunk);

    // hashcat 大量使用裸 \r 做行内覆盖，必须同时按 \r 和 \n 切分，
    // 否则多行内容会挤成一条超长记录，界面上看不到任何滚动。
    final parts = chunk.split(RegExp(r'\r\n|\r|\n'));
    for (final raw in parts) {
      final line = raw.trim();
      if (line.isEmpty) continue;
      // 跳过纯交互提示，这类只在 TTY 下有意义，放进日志只会干扰
      if (line.startsWith('[s]tatus [p]ause')) continue;

      if (stderr) {
        onLog?.call('[stderr] $line');
        _log(log, '[stderr] $line');
        if (line.contains('No hashes loaded') ||
            line.contains('Token length exception') ||
            line.contains('Separator unmatched') ||
            line.contains('Invalid hash') ||
            line.contains('Hash-length exception') ||
            line.contains('Line-length exception')) {
          _hashFormatError = line.trim();
        }
        final envErr = translateEnvError(line);
        if (envErr != null) _envError = envErr;
      } else {
        onLog?.call(line);
        _log(log, line);
      }
    }
  }

  void _parseStatusObject(Map<String, dynamic> m) {
    try {
      final status = m['status'] as int?;

      // 每块设备的速度为 H/s，需要累加；顶层并没有 speed 字段。
      int speedHs = 0;
      final devices = m['devices'];
      if (devices is List) {
        for (final d in devices) {
          if (d is Map) {
            speedHs += (d['speed'] as num?)?.toInt() ?? 0;
          }
        }
      }
      final speedKhs = speedHs ~/ 1000;
      // 记下实测速度，供暴力破解面板估算耗时（预计耗时必须基于真实机器性能，
      // 凭空给一个数字会让用户在「要不要跑 8 小时」的决策上被误导）。
      if (speedHs > 0) _lastSpeedPerSec = speedHs;

      final progress = m['progress'] as List?;
      int tested = 0, total = 0;
      if (progress is List && progress.length >= 2) {
        tested = (progress[0] as num).toInt();
        total = (progress[1] as num).toInt();
      }

      // recovered_hashes = [已破解, 总数]，比 status 更可靠
      int recovered = 0;
      final rec = m['recovered_hashes'];
      if (rec is List && rec.isNotEmpty) {
        recovered = (rec[0] as num?)?.toInt() ?? 0;
      }
      final cracked = status == 3 || recovered > 0;

      // estimated_stop 是 Unix 秒时间戳，不是 ISO 字符串
      int etaSec = 0;
      final stop = m['estimated_stop'];
      if (stop is num && stop > 0) {
        final nowSec = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        etaSec = stop.toInt() - nowSec;
        if (etaSec < 0) etaSec = 0;
      } else if (stop is String) {
        final parsed = DateTime.tryParse(stop);
        if (parsed != null) {
          etaSec = parsed.difference(DateTime.now()).inSeconds;
          if (etaSec < 0) etaSec = 0;
        }
      }
      final prog = (total > 0) ? (tested / total) : 0.0;
      _lastTestedCount = tested;
      _lastTotalCount = total;
      onProgress?.call(HashcatProgress(
        progress: prog.clamp(0.0, 1.0),
        speedKhs: speedKhs,
        etaSeconds: etaSec,
        testedCount: tested,
        totalCount: total,
        status: HashcatStatus.fromCode(status ?? 0),
        cracked: cracked,
      ));
    } catch (_) {
      // 解析失败不影响攻击本身，静默跳过即可
    }
  }


  /// 读取 hashcat 输出文件里的候选密码。
  /// 可能有多个（弱校验模式 + --keep-guessing），需要进一步验证。
  Future<List<String>> _readCandidates(String outFile) async {
    try {
      final f = File(outFile);
      if (!await f.exists()) return const [];
      final content = await f.readAsString();
      final out = <String>[];
      for (final l in content.split('\n')) {
        final t = l.trim();
        if (t.isEmpty) continue;
        final idx = t.lastIndexOf(':');
        final cand = (idx > 0 && idx < t.length - 1) ? t.substring(idx + 1) : t;
        // 去重但保持顺序
        if (!out.contains(cand)) out.add(cand);
      }
      return out;
    } catch (_) {
      return const [];
    }
  }

  Future<String> _readOutputWithNote(
      String outFile, StringBuffer? log) async {
    final candidates = await _readCandidates(outFile);
    final buf = log ?? StringBuffer();
    return await _resolvePassword(candidates, buf) ?? '';
  }

  /// 用内置 Python 逐个试解原始文件，挑出真正能解开的密码。
  Future<String?> _verifyCandidates(List<String> candidates) async {
    if (_sourceFile.isEmpty) return null;
    if (!await File(_sourceFile).exists()) return null;
    // 只校验 ZIP：--keep-guessing 目前只在 ZipCrypto 系列模式上开启
    if (!_sourceFile.toLowerCase().endsWith('.zip')) return null;

    final py = pythonPath.isNotEmpty ? pythonPath : AppPaths.pythonExe;
    if (py.isEmpty || !await File(py).exists()) return null;

    final script = p.join(AppPaths.toolsDir, 'verify_zip.py');
    if (!await File(script).exists()) return null;

    final tmp = Directory.systemTemp;
    final candFile = p.join(tmp.path, 'hc_cand_${_hashType}.txt');
    final outFile = p.join(tmp.path, 'hc_verified_${_hashType}.txt');
    try {
      await File(candFile).writeAsString(candidates.join('\n'));
      final r = await Process.run(
        py,
        [script, _sourceFile, candFile, outFile],
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
      ).timeout(const Duration(seconds: 120));
      final f = File(outFile);
      if (!await f.exists()) return null;
      final lines = (await f.readAsString())
          .split('\n')
          .map((e) => e.trim())
          .where((e) => e.isNotEmpty)
          .toList();
      if (lines.isEmpty) {
        final err = (r.stderr as String? ?? '').trim();
        if (err.isNotEmpty) _log(StringBuffer(), '候选验证: $err');
        return null;
      }
      return lines.first;
    } catch (_) {
      return null;
    }
  }

  /// 默认掩码集合。
  ///
  /// 注意：掩码空间随长度指数增长，?a?a?a?a?a?a 有 95^6 ≈ 7350 亿种组合，
  /// 在消费级显卡上要跑好几天——放进默认策略就等于「点了以后永远没反应」。
  /// 这里只保留分钟级能穷尽的组合，并按常见密码习惯加几个结构化掩码；
  /// 更长/更复杂的组合交给用户自定义掩码。
  List<String> _defaultMasks() => [
        '?d?d?d?d', // 4 位纯数字
        '?d?d?d?d?d', // 5 位纯数字
        '?d?d?d?d?d?d', // 6 位纯数字
        '?d?d?d?d?d?d?d', // 7 位纯数字
        '?d?d?d?d?d?d?d?d', // 8 位纯数字（手机号后 8 位）
        '?l?l?l?l', // 4 位小写
        '?l?l?l?l?l', // 5 位小写
        '?l?l?l?l?l?l', // 6 位小写
        '?u?l?l?l?l?l', // 首字母大写 + 小写（Name 型）
        '?u?l?l?l?l?l?d?d', // 首字母大写 + 数字后缀
        '?l?l?l?l?l?l?d?d', // 小写单词 + 2 位数字
      ];

  /// 把 hashcat 原始的英文环境报错翻译成中文可执行的指引。
  /// hashcat 本身不自带 OpenCL 运行库，裸机（没装显卡驱动 / 虚拟机）上
  /// 最常见的失败就是找不到 OpenCL 平台，必须明确告诉用户该怎么办。
  static String? translateEnvError(String line) {
    final l = line.toLowerCase();
    if (l.contains('no opencl') ||
        l.contains('clgetplatformids') ||
        l.contains('no devices found') ||
        l.contains('failed to find opencl') ||
        l.contains('opencl runtime')) {
      return '未找到可用的 OpenCL 运行环境。\n\n'
          'hashcat 依赖显卡的 OpenCL 驱动才能计算。请按下列顺序排查：\n'
          '1. 安装/更新显卡驱动（NVIDIA / AMD / Intel 官网下载最新版）\n'
          '2. 笔记本请确认已切换到独立显卡运行本软件\n'
          '3. 虚拟机环境通常无法提供 OpenCL，需在物理机上运行';
    }
    if (l.contains('cuda sdk toolkit') || l.contains('nvrtc')) {
      return '显卡驱动已加载，但 CUDA 工具包不完整，hashcat 已自动回退到 OpenCL 模式。'
          '（一般不影响使用；如需完整性能可安装 CUDA Toolkit）';
    }
    if (l.contains('out of memory') || l.contains('clcreatebuffer')) {
      return '显存不足。可在设置中降低破解强度，或关闭其他占用显卡的程序后重试。';
    }
    if (l.contains('kernel') && l.contains('build')) {
      return 'OpenCL 内核编译失败，通常是驱动版本过旧。请更新显卡驱动后重试。';
    }
    return null;
  }

  /// 启动自检：探测当前机器的可用计算后端。
  /// 返回可直接展示给用户的中文报告。
  static Future<String> checkEnvironment(String hashcatPath) async {
    if (hashcatPath.isEmpty || !File(hashcatPath).existsSync()) {
      return 'hashcat 未找到。请确认软件已完整解压，runtime\\hashcat 目录存在。';
    }
    try {
      final r = await Process.run(
        hashcatPath,
        ['-I'],
        workingDirectory: File(hashcatPath).parent.path,
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
      ).timeout(const Duration(seconds: 60));
      final out = '${r.stdout}\n${r.stderr}';
      final devices = <String>[];
      for (final line in out.split('\n')) {
        final t = line.trim();
        if (t.startsWith('Backend Device ID') ||
            (t.startsWith('Name') && t.contains(':'))) {
          devices.add(t);
        }
      }
      final envErr = translateEnvError(out);
      if (envErr != null) return envErr;
      if (devices.isEmpty) {
        return '未探测到可用计算设备。请确认已安装显卡驱动（OpenCL 运行环境）。';
      }
      return '计算设备正常：\n${devices.join('\n')}';
    } catch (e) {
      return '环境自检失败: $e';
    }
  }

  void _log(StringBuffer buf, String s) {
    buf.writeln(s);
  }

}

class _RunResult {
  final bool cracked;
  final String password;
  final String error;
  const _RunResult(this.cracked, this.password, [this.error = '']);
}

/// 一轮攻击共用的临时文件路径与日志缓冲。
/// [early] 只应该在「无需继续攻击」时被赋值（初始化失败 / 落盘失败 / 命中缓存）。
class _RunContext {
  final String hashFile;
  final String outFile;
  final String potFile;
  final StringBuffer log = StringBuffer();
  HashcatResult? early;

  _RunContext({
    required this.hashFile,
    required this.outFile,
    required this.potFile,
  });
}
