import 'dart:io';
import 'dart:convert';
import '../models/file_type.dart';
import '../models/file_signatures.dart';
import '../utils/platform_utils.dart';
import 'app_paths.dart';
import 'hash_identifier.dart';

class ExtractResult {
  final bool success;
  final String hash;

  /// 首选 hashcat 模式。
  final int hashType;

  /// 候选模式（按常见程度排序）。
  ///
  /// 有些哈希在结构上同时符合多个模式（32 位十六进制既可能是 MD5 也可能是
  /// NTLM/MD4），hashcat 自己也拒绝替我们猜。这里给出候选列表，让破解阶段
  /// 按顺序逐个试，比硬猜一个然后失败要好得多。
  final List<int> hashTypes;

  final String rawOutput;
  final String error;

  const ExtractResult({
    this.success = false,
    this.hash = '',
    this.hashType = 0,
    this.hashTypes = const [],
    this.rawOutput = '',
    this.error = '',
  });

  factory ExtractResult.ok(String hash, int hashType, String raw,
          {List<int> hashTypes = const []}) =>
      ExtractResult(
        success: true,
        hash: hash,
        hashType: hashType,
        hashTypes: hashTypes.isEmpty ? [hashType] : hashTypes,
        rawOutput: raw,
      );

  factory ExtractResult.fail(String error, [String raw = '']) =>
      ExtractResult(success: false, error: error, rawOutput: raw);
}

class _DebugLog {
  static void write(String msg) {
    try {
      final logDir = '${Platform.environment['APPDATA']}${Platform.pathSeparator}com.hashcrack${Platform.pathSeparator}hashcat_gui${Platform.pathSeparator}hashcrack';
      Directory(logDir).createSync(recursive: true);
      final logFile = File('$logDir${Platform.pathSeparator}extractor_debug.log');
      final ts = DateTime.now().toIso8601String();
      logFile.writeAsStringSync('[$ts] $msg\n', mode: FileMode.append);
    } catch (_) {}
  }
}

class ExtractorService {
  final String toolsDir;
  final String? pythonPath;
  final void Function(String line)? onLog;

  ExtractorService({
    required this.toolsDir,
    this.pythonPath,
    this.onLog,
  });

  Future<ExtractResult> extract(String filePath, DetectedFileType type) async {
    _DebugLog.write('=== extract called ===');
    _DebugLog.write('filePath: $filePath');
    _DebugLog.write('fileType: $type');
    _DebugLog.write('toolsDir: $toolsDir');
    _DebugLog.write('pythonPath: $pythonPath');
    try {
      final result = await _extractInternal(filePath, type);
      _DebugLog.write('extract result: success=${result.success}, hashType=${result.hashType}, error=${result.error}');
      return result;
    } catch (e, st) {
      _DebugLog.write('extract EXCEPTION: $e');
      _DebugLog.write('stacktrace: $st');
      return ExtractResult.fail('提取异常: $e');
    }
  }

  Future<ExtractResult> _extractInternal(String filePath, DetectedFileType type) async {
    switch (type) {
      case DetectedFileType.zip:
        return _extractZip(filePath);
      case DetectedFileType.pdf:
        return _extractPdf(filePath);
      case DetectedFileType.officeNew:
        return _runOfficeNew(filePath);
      case DetectedFileType.officeOld:
        return _runTool('office2john', filePath, 9700);
      case DetectedFileType.wifiPcap:
      case DetectedFileType.pcapng:
        return _extractWifi(filePath);
      case DetectedFileType.hashFile:
        return _loadHashFile(filePath);
      // MIFARE 转储和 nonce 日志不该走到这里：它们在主界面就被分流到
      // MIFARE 分析器了，hashcat 没有对应的哈希模式。这里显式给出提示，
      // 免得将来有人改动了分流逻辑却拿到一句莫名其妙的「无法识别」。
      case DetectedFileType.mifareDump:
        return ExtractResult.fail(
            'MIFARE 卡片转储不支持 hashcat 破解，请使用「MIFARE 卡片分析器」');
      case DetectedFileType.nonceLog:
        return ExtractResult.fail(
            'MIFARE nonce 日志请使用「MIFARE 卡片分析器 → 密钥恢复」处理');
      case DetectedFileType.unknown:
        return ExtractResult.fail('无法识别的文件类型');
      default:
        // 其余全部类型由注册表描述怎么提取（或不提取）。
        return _extractByRegistry(filePath, type);
    }
  }

  /// 按注册表里登记的提取器分发。
  ///
  /// 这一层让「新增一种文件类型」变成纯数据工作：只要在
  /// `file_signatures.dart` 里把 extractor 填对，这里不用再改。
  Future<ExtractResult> _extractByRegistry(
      String filePath, DetectedFileType type) async {
    final sig = type.signature;
    final spec = sig.extractor;

    if (spec.startsWith('hc:')) {
      return _runHashcatTool(filePath, type, spec.substring(3));
    }
    if (spec.startsWith('john:')) {
      return _runJohnGeneric(filePath, type, spec.substring(5));
    }
    if (spec.startsWith('builtin:')) {
      return _extractWifi(filePath);
    }
    // 没有内置提取器 —— 给出可执行的中文指引，而不是一句「失败」
    return _guidance(type);
  }

  /// 对「已识别但本软件没有内置提取器」的类型给出明确的操作指引。
  ///
  /// 这类提示必须写清楚「用什么工具、得到什么开头、用哪个模式」，
  /// 否则用户只知道失败了却不知道下一步做什么。
  ExtractResult _guidance(DetectedFileType type) {
    final sig = type.signature;
    final buf = StringBuffer()
      ..writeln('已识别为「${sig.label}」，但本软件没有内置它的哈希提取器。')
      ..writeln();
    if (sig.modes.isNotEmpty) {
      buf.writeln('对应的 hashcat 模式：${sig.modeHint}');
      buf.writeln();
    }
    buf.writeln(sig.guidance.isNotEmpty
        ? sig.guidance
        : '可先自行提取出哈希文本，再把哈希拖进来破解。');
    return ExtractResult.fail(buf.toString());
  }

  /// 用 hashcat 自带的官方转换器（`runtime/hashcat/tools/*2hashcat.py`）提取哈希。
  ///
  /// 为什么优先用它们而不是第三方脚本：这些脚本随 hashcat 一起发布、同版本
  /// 维护，输出的哈希格式与当前 hashcat 内核严格对应，不会出现「工具产出的
  /// 哈希新内核不认」的错配。实测 TrueCrypt 就是这种坑：旧的 6211 模式已经
  /// 加载不了 `$truecrypt$` 形式的哈希了。
  Future<ExtractResult> _runHashcatTool(
      String filePath, DetectedFileType type, String script) async {
    final toolsDir = AppPaths.hashcatToolsDir;
    if (toolsDir.isEmpty) {
      return ExtractResult.fail(
          '未找到 hashcat 自带的转换工具目录（runtime/hashcat/tools）。\n'
          '请确认软件已完整解压。');
    }
    final py = _resolvePython();
    if (py == null) {
      return ExtractResult.fail(
          '未找到可用的 Python 环境，无法运行 $script。\n'
          '请确认 runtime/python 目录存在。');
    }
    final scriptPath =
        '$toolsDir${Platform.pathSeparator}$script.py';
    if (!await File(scriptPath).exists()) {
      return ExtractResult.fail('转换脚本不存在: $scriptPath');
    }

    // 个别脚本的入参形式不同，这里逐个适配；
    // 其余绝大多数都接受「第一个位置参数就是目标文件」。
    final args = <String>[];
    String? redirectOutput;
    Directory? tmpDir;
    switch (script) {
      case 'vmwarevmx2hashcat':
        args.addAll(['--vmx', filePath]);
        break;
      case 'veeamvbk2hashcat':
        args.addAll(['-f', filePath]);
        break;
      case 'metamask2hashcat':
        args.addAll(['--vault', filePath]);
        break;
      case 'shiro1-to-hashcat':
        // 这个脚本只接受「目录 + 输出文件」，需要先把目标文件挪进临时目录
        tmpDir = await Directory.systemTemp.createTemp('hc_shiro_');
        final copied = File(
            '${tmpDir.path}${Platform.pathSeparator}${filePath.split(RegExp(r'[/\\]')).last}');
        await File(filePath).copy(copied.path);
        redirectOutput =
            '${tmpDir.path}${Platform.pathSeparator}out.txt';
        args.addAll([tmpDir.path, redirectOutput]);
        break;
      default:
        args.add(filePath);
    }

    onLog?.call('调用 $script: $py $scriptPath ${args.join(' ')}');
    final r = await Process.run(py, [scriptPath, ...args],
        stdoutEncoding: null, stderrEncoding: null);
    final stdoutStr = String.fromCharCodes(r.stdout as List<int>);
    final stderrStr = String.fromCharCodes(r.stderr as List<int>);

    // shiro 的哈希写在输出文件里
    var haystack = stdoutStr;
    if (redirectOutput != null) {
      try {
        final f = File(redirectOutput);
        if (await f.exists()) haystack = '${await f.readAsString()}\n$haystack';
      } catch (_) {}
    }
    if (tmpDir != null) {
      try {
        await tmpDir.delete(recursive: true);
      } catch (_) {}
    }

    final hash = _extractHashFromOutput(haystack);
    if (hash.isEmpty) {
      final detail = stderrStr.trim().isNotEmpty
          ? stderrStr.trim()
          : (stdoutStr.trim().isEmpty ? '（无任何输出）' : stdoutStr.trim());
      return ExtractResult.fail(
          '${type.label} 哈希提取失败（$script）。\n$detail',
          stdoutStr);
    }

    final modes = _modeCandidatesForHash(hash);
    if (modes.isEmpty) {
      return ExtractResult.fail(
          '提取到哈希但无法确定对应的 hashcat 模式：\n$hash', stdoutStr);
    }
    return ExtractResult.ok(hash, modes.first, stdoutStr, hashTypes: modes);
  }

  /// 从转换脚本的输出里抠出哈希本体。
  ///
  /// 各脚本的输出五花八门：有的直接打印哈希，有的前面还有一堆
  /// 「[+] Parsing FVEK...」之类的进度信息，还有的把哈希混在句子里
  /// （`Found password hash: $bitlocker$1$...`）。统一按「找到第一个
  /// `$标签$` 或已知纯文本前缀」来处理。
  static String _extractHashFromOutput(String output) {
    final dollarPrefix = RegExp(r'^\$[A-Za-z0-9_]+\$');
    for (final raw in output.split(RegExp(r'\r\n|\r|\n'))) {
      final line = raw.trim();
      if (line.isEmpty) continue;
      if (line.startsWith('EXODUS:')) return line;
      if (line.startsWith('WPA*')) return line;
      // 从行内第一个 '$' 开始截，兼容「Found password hash: $xxx$...」
      final i = line.indexOf(r'$');
      if (i < 0) continue;
      final cand = line.substring(i).trim();
      // 去掉可能粘在末尾的括号说明
      final cleaned = cand.split(RegExp(r'\s')).first;
      if (dollarPrefix.hasMatch(cleaned)) return cleaned;
    }
    return '';
  }

  /// 由哈希内容推断候选的 hashcat 模式。
  static List<int> _modeCandidatesForHash(String hash) {
    final cands = HashIdentifier.fallbackCandidates(hash);
    return cands.map((c) => c.mode).toList();
  }

  /// 通用 john 脚本提取（zip2john 之外的类型）。
  ///
  /// 目前注册表里走这条路的类型都已有专门实现（zip/pdf/office），
  /// 这里保留入口是为了以后补 john 脚本时不必再改路由逻辑。
  Future<ExtractResult> _runJohnGeneric(
      String filePath, DetectedFileType type, String tool) async {
    final result = await _invokeTool(tool, [filePath]);
    if (!result.success) {
      return ExtractResult.fail('提取失败 ($tool): ${result.stderr}', result.stdout);
    }
    final hash = _parseHashLine(result.stdout);
    if (hash.isEmpty) {
      return ExtractResult.fail('未提取到哈希 ($tool)', result.stdout);
    }
    final modes = _modeCandidatesForHash(hash);
    if (modes.isEmpty) {
      return ExtractResult.fail('无法确定哈希模式:\n$hash', result.stdout);
    }
    return ExtractResult.ok(hash, modes.first, result.stdout, hashTypes: modes);
  }

  Future<ExtractResult> _runTool(
      String toolName, String filePath, int hashType) async {
    final result = await _invokeTool(toolName, [filePath]);
    if (!result.success) {
      return ExtractResult.fail(
          '提取失败 (${toolName}): ${result.stderr}', result.stdout);
    }
    final hash = _parseHashLine(result.stdout);
    if (hash.isEmpty) {
      return ExtractResult.fail(
          '未提取到哈希 (${toolName})，原始输出: ${result.stdout}', result.stdout);
    }
    return ExtractResult.ok(hash, hashType, result.stdout);
  }

  Future<ExtractResult> _extractZip(String filePath) async {
    _DebugLog.write('--- _extractZip ---');
    _DebugLog.write('filePath: $filePath');
    final result = await _invokeTool('zip2john', [filePath]);
    _DebugLog.write('zip2john result: success=${result.success}, stderr=${result.stderr}');

    if (!result.success) {
      return ExtractResult.fail(
          'ZIP 哈希提取失败: ${result.stderr}', result.stdout);
    }
    String hashCandidate = _parseHashLine(result.stdout);
    _DebugLog.write('parseHashLine result: $hashCandidate');

    if (hashCandidate.isEmpty) {
      return ExtractResult.fail('未提取到 ZIP 哈希（工具输出可能不含哈希行）', result.stdout);
    }

    int hashType;
    String finalHash;

    // Check for zip2 format (type 13600)
    if (hashCandidate.endsWith('\$/zip2\$')) {
      hashType = 13600; // WinZip AES
      if (!hashCandidate.startsWith('\$zip2\$')) {
        // If it ends with $/zip2$ but doesn't start with $zip2$, prepend it.
        finalHash = '\$zip2\$' + hashCandidate;
      } else {
        finalHash = hashCandidate;
      }
    } else if (hashCandidate.contains('\$pkzip2\$') || hashCandidate.contains('\$pkzip\$')) {
      final stderrLower = result.stderr.toLowerCase();
      if (stderrLower.contains('17210')) {
        hashType = 17210; // PKZIP Uncompressed
      } else if (stderrLower.contains('17220')) {
        hashType = 17220;
      } else if (stderrLower.contains('17225')) {
        hashType = 17225;
      } else {
        hashType = 17200; // PKZIP Compressed (default)
      }
      finalHash = hashCandidate;
    } else {
      // Default to PKZIP Compressed if no specific markers are found
      hashType = 17200;
      finalHash = hashCandidate;
    }
    _DebugLog.write('finalHash (first 100): ${finalHash.length > 100 ? finalHash.substring(0, 100) : finalHash}');
    _DebugLog.write('hashType: $hashType');
    return ExtractResult.ok(finalHash, hashType, result.stdout);
  }

  Future<ExtractResult> _extractPdf(String filePath) async {
    final result = await _invokeTool('pdf2john', [filePath]);
    if (!result.success) {
      return ExtractResult.fail(
          'PDF 哈希提取失败: ${result.stderr}', result.stdout);
    }
    final hash = _parseHashLine(result.stdout);
    if (hash.isEmpty) {
      return ExtractResult.fail('未提取到 PDF 哈希', result.stdout);
    }
    final hashType = _pdfHashType(hash);
    return ExtractResult.ok(hash, hashType, result.stdout);
  }

  Future<ExtractResult> _runOfficeNew(String filePath) async {
    final result = await _invokeTool('office2john', [filePath]);
    if (!result.success) {
      return ExtractResult.fail(
          'Office 哈希提取失败: ${result.stderr}', result.stdout);
    }
    final hash = _parseHashLine(result.stdout);
    if (hash.isEmpty) {
      return ExtractResult.fail('未提取到 Office 哈希', result.stdout);
    }
    final hashType = _officeHashType(hash);
    return ExtractResult.ok(hash, hashType, result.stdout);
  }

  Future<ExtractResult> _extractWifi(String filePath) async {
    _DebugLog.write('--- _extractWifi ---');
    _DebugLog.write('filePath: $filePath');
    String? hcxError;
    // Try hcxpcapngtool.exe first (real compiled tool)
    final hcxExePath = _resolveHcxpcapngtoolPath();
    _DebugLog.write('hcxExePath: $hcxExePath');
    if (hcxExePath != null && File(hcxExePath).existsSync()) {
      final hashFile =
          '${Directory.systemTemp.absolute.path}${Platform.pathSeparator}wifi_hash_${DateTime.now().millisecondsSinceEpoch}.txt';
      try {
        // Set working directory to hcxtools dir so DLLs are found
        final hcxWorkingDir = File(hcxExePath).parent.path;
        final r = await Process.run(hcxExePath, ['--all', '-o', hashFile, filePath],
            workingDirectory: hcxWorkingDir,
            stdoutEncoding: null, stderrEncoding: null);
        final stdoutStr = String.fromCharCodes(r.stdout as List<int>);
        final stderrStr = String.fromCharCodes(r.stderr as List<int>);
        onLog?.call('hcxpcapngtool: $hcxExePath --all -o $hashFile $filePath');
        if (stderrStr.isNotEmpty) {
          onLog?.call('hcxpcapngtool stderr: $stderrStr');
        }
        // Read the output hash file
        final hashFileObj = File(hashFile);
        if (await hashFileObj.exists()) {
          final content = await hashFileObj.readAsString();
          final lines = content.split('\n').where((l) => l.trim().isNotEmpty);
          if (lines.isNotEmpty) {
            final hash = lines.first.trim();
            onLog?.call('提取到 WiFi 哈希: ${hash.substring(0, hash.length > 60 ? 60 : hash.length)}...');
            // Clean up temp file
            try { await hashFileObj.delete(); } catch (_) {}
            return ExtractResult.ok(hash, 22000, stdoutStr + '\n' + stderrStr);
          }
          // Clean up
          try { await hashFileObj.delete(); } catch (_) {}
        }
        // No hash extracted - check for common issues
        String errorMsg = '未从握手包提取到有效哈希';
        if (stderrStr.contains('no hashes written') || stdoutStr.contains('no hashes written')) {
          errorMsg = '握手包不完整，无法提取哈希。需要至少包含 M1+M2 或 M1+M3 EAPOL 消息。';
        }
        if (stdoutStr.contains('missing frames') || stderrStr.contains('missing frames')) {
          errorMsg += '\n提示: 握手包缺少必要的帧（BEACON、EAPOL M3 等）。';
        }
        // 不在这里直接返回失败：hcxpcapngtool 对部分网卡导出的 radiotap pcap
        // 会只读到前几帧就报 "packet read error"，此时抓包里其实有完整握手。
        // 继续走下面的内置 Python 解析器兜底。
        hcxError = errorMsg;
        onLog?.call('hcxpcapngtool 未产出哈希，改用内置 802.11 解析器重试');
        _DebugLog.write('hcxpcapngtool no hash: $errorMsg (raw=${stdoutStr.length}B/${stderrStr.length}B)');
      } catch (e) {
        hcxError = 'hcxpcapngtool 执行失败: $e';
        _DebugLog.write('hcxpcapngtool exception: $e');
      }
    }

    // 兜底 1：内置 pcap2hashcat.py —— 纯 Python 解析 802.11 帧生成 22000 哈希，
    // 不依赖 hcxtools，能处理 hcxpcapngtool 读不了的抓包。
    final py = await _invokeTool('pcap2hashcat', [filePath]);
    if (py.success) {
      final wpa = py.stdout
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.startsWith('WPA*'))
          .toList();
      if (wpa.isNotEmpty) {
        onLog?.call('内置解析器提取到 ${wpa.length} 条候选哈希');
        return ExtractResult.ok(wpa.first, 22000, py.stdout);
      }
    }
    _DebugLog.write('pcap2hashcat fallback failed: ${py.stderr}');

    // 兜底 2：Python hcxpcaptool
    final result = await _invokeTool('hcxpcaptool', ['--type=22000', filePath]);
    if (result.success) {
      final out = result.stdout.trim();
      final firstLine =
          out.isEmpty ? '' : out.split('\n').first.trim();
      if (firstLine.isNotEmpty) {
        return ExtractResult.ok(firstLine, 22000, result.stdout);
      }
    }

    return ExtractResult.fail(
        hcxError ??
            'WiFi 握手包转换失败：抓包中未找到可用的 WPA/WPA2 握手\n'
                '需要至少包含 M1+M2、M1+M4、M2+M3 或 M3+M4 之一，以及 BEACON（含 ESSID）。',
        'pcap2hashcat: ${py.stderr}\n${result.stdout}');
  }

  Future<ExtractResult> _loadHashFile(String filePath) async {
    try {
      final content = await File(filePath).readAsString();
      final line = content.split('\n').first.trim();
      if (line.isEmpty) {
        return ExtractResult.fail('哈希文件为空');
      }

      // 用 hashcat 自带的 `--identify` 判定类型。
      //
      // 这里以前是写死 hashType=0（等于 MD5），等于「不管什么哈希都按 MD5 跑」，
      // 用户贴一段 NTLM 或者 sha512crypt 进来必然失败还找不到原因。
      // 现在交给 hashcat 自己认——它认得 580 多种模式，远比我手写规则靠谱。
      final identifier = HashIdentifier(hashcatPath: AppPaths.hashcatExe);
      final id = await identifier.identify(content);

      if (id.candidates.isNotEmpty) {
        final buffer = StringBuffer(content.trim());
        if (id.ambiguous) {
          buffer.write('\n\n识别到 ${id.candidates.length} 个结构相符的模式，'
              '将按常见程度依次尝试：');
          buffer.write(id.candidates
              .take(HashIdentifier.maxCandidates)
              .map((c) => '${c.mode}（${c.name}）')
              .join('、'));
        } else {
          buffer.write('\n\n识别为 ${id.candidates.first.mode}'
              '（${id.candidates.first.name}）');
        }
        if (id.note.isNotEmpty) buffer.write('\n${id.note}');
        return ExtractResult.ok(line, id.primaryMode, buffer.toString(),
            hashTypes: id.modes);
      }

      // 认不出来也别直接判死：把说明带上，让用户知道发生了什么
      return ExtractResult.ok(
        line,
        0,
        '${content.trim()}\n\n'
            '未能自动识别这段哈希的类型${id.note.isEmpty ? '' : '（${id.note}）'}，'
            '将默认按 -m 0（MD5）尝试。若确认是别的类型，'
            '可先用 hashcat --identify 查一下模式号。',
      );
    } catch (e) {
      return ExtractResult.fail('读取哈希文件失败: $e');
    }
  }

  Future<_ToolResult> _invokeTool(String name, List<String> args) async {
    _DebugLog.write('--- _invokeTool: $name ${args.join(' ')} ---');

    final exePath = _resolveToolPath(name, exe: true);
    if (exePath != null && await File(exePath).exists()) {
      _DebugLog.write('Found exe: $exePath');
      onLog?.call('调用 $name: $exePath ${args.join(' ')}');
      return _runProcess(exePath, args);
    }
    _DebugLog.write('No exe found at: $exePath');

    final pyPath = _resolveToolPath(name, exe: false);
    if (pyPath != null && await File(pyPath).exists()) {
      _DebugLog.write('Found py: $pyPath');
      final py = _resolvePython();
      if (py == null) {
        _DebugLog.write('Python NOT detected!');
        return _ToolResult(false, '',
            '未找到 Python 环境，且软件内置的便携 Python 缺失。\n'
            '请确认软件压缩包已完整解压（runtime\\python 目录应存在）。');
      }
      _DebugLog.write('Python detected: $py');
      onLog?.call('调用 $name (Python): $py $pyPath ${args.join(' ')}');
      return _runProcess(py, [pyPath, ...args]);
    }
    _DebugLog.write('No py found at: $pyPath');

    final embedded = await _tryEmbeddedExtractor(name, args);
    if (embedded != null) return embedded;
    _DebugLog.write('Tool $name not found anywhere! toolsDir=$toolsDir');
    return _ToolResult(false, '',
        '提取工具 $name 未找到。工具目录: $toolsDir');
  }

  String? _resolveToolPath(String name, {required bool exe}) {
    final suffix = exe
        ? (PlatformUtils.isWindows ? '.exe' : '')
        : '.py';
    final candidate = '$toolsDir${Platform.pathSeparator}$name$suffix';
    return candidate;
  }

  /// 定位 hcxpcapngtool（把 WiFi 握手包转成 hashcat 22000 格式）。
  /// 全部通过 AppPaths 相对解析，不依赖任何写死的绝对路径。
  String? _resolveHcxpcapngtoolPath() {
    // 优先用 AppPaths 从 runtime/tools/hcxtools 里找
    final fromPaths = AppPaths.hcxpcapngtoolExe;
    if (fromPaths.isNotEmpty) return fromPaths;

    final exeName =
        PlatformUtils.isWindows ? 'hcxpcapngtool.exe' : 'hcxpcapngtool';
    final candidates = <String>[
      // 用户自定义工具目录下的 hcxtools
      '$toolsDir${Platform.pathSeparator}hcxtools${Platform.pathSeparator}$exeName',
      // 用户自定义工具目录
      '$toolsDir${Platform.pathSeparator}$exeName',
    ];
    for (final c in candidates) {
      if (File(c).existsSync()) return c;
    }
    return null;
  }

  /// 解析实际使用的 Python 解释器。
  ///
  /// 优先级：用户在设置里指定的路径 → 软件内置的便携 Python（runtime/python）
  /// → 系统安装的 Python。前两级命中就意味着目标机器不需要装 Python。
  String? _resolvePython() {
    // 1) 用户显式指定
    if (pythonPath != null && pythonPath!.isNotEmpty) {
      if (File(pythonPath!).existsSync()) return pythonPath;
    }
    // 2) 内置便携 Python（零依赖的关键）
    final bundled = AppPaths.pythonExe;
    if (bundled.isNotEmpty && File(bundled).existsSync()) {
      _DebugLog.write('使用内置 Python: $bundled');
      return bundled;
    }
    // 3) 系统 Python 兜底
    return _detectPython();
  }

  String? _detectPython() {
    _DebugLog.write('--- _detectPython ---');
    if (!PlatformUtils.isWindows) {
      for (final cmd in ['python3', 'python']) {
        try {
          final r = Process.runSync('which', [cmd]);
          _DebugLog.write('which $cmd: exit=${r.exitCode}');
          if (r.exitCode == 0) {
            final path = (r.stdout as String).trim().split('\n').first.trim();
            if (path.isNotEmpty) return path;
          }
        } catch (_) {}
      }
      _DebugLog.write('No python found on non-Windows');
      return null;
    }

    // Method 1: py -3 launcher
    try {
      final r = Process.runSync('py', ['-3', '-c', 'import sys; print(sys.executable)']);
      _DebugLog.write('py -3: exit=${r.exitCode}, stdout=${(r.stdout as String).trim()}');
      if (r.exitCode == 0) {
        final path = (r.stdout as String).trim();
        if (path.isNotEmpty && File(path).existsSync()) {
          _DebugLog.write('Python found via py -3: $path');
          return path;
        }
      }
    } catch (e) {
      _DebugLog.write('py -3 exception: $e');
    }

    // Method 2: py launcher
    try {
      final r = Process.runSync('py', ['-c', 'import sys; print(sys.executable)']);
      _DebugLog.write('py: exit=${r.exitCode}, stdout=${(r.stdout as String).trim()}');
      if (r.exitCode == 0) {
        final path = (r.stdout as String).trim();
        if (path.isNotEmpty && File(path).existsSync()) return path;
      }
    } catch (e) {
      _DebugLog.write('py exception: $e');
    }

    // Method 3: where command
    for (final cmd in ['python.exe', 'python3.exe', 'python']) {
      try {
        final r = Process.runSync('where', [cmd]);
        _DebugLog.write('where $cmd: exit=${r.exitCode}');
        if (r.exitCode == 0) {
          final lines = (r.stdout as String).trim().split('\n');
          for (final line in lines) {
            final path = line.trim();
            if (path.isNotEmpty && File(path).existsSync()) {
              try {
                final vr = Process.runSync(path, ['--version']);
                if (vr.exitCode == 0) {
                  _DebugLog.write('Python found via where: $path');
                  return path;
                }
              } catch (_) {}
            }
          }
        }
      } catch (_) {}
    }

    // Method 4: common install paths
    final commonPaths = [
      r'C:\Python311\python.exe',
      r'C:\Python310\python.exe',
      r'C:\Python39\python.exe',
      r'C:\Python38\python.exe',
      r'C:\Python37\python.exe',
      r'C:\Program Files\Python311\python.exe',
      r'C:\Program Files\Python310\python.exe',
      r'C:\Program Files\Python39\python.exe',
      r'C:\Program Files\Python38\python.exe',
      r'C:\Program Files (x86)\Python311\python.exe',
      r'C:\Program Files (x86)\Python310\python.exe',
      r'C:\Program Files (x86)\Python39\python.exe',
      Platform.environment['LOCALAPPDATA'] != null
          ? '${Platform.environment['LOCALAPPDATA']}\\Programs\\Python\\Python311\\python.exe'
          : '',
      Platform.environment['LOCALAPPDATA'] != null
          ? '${Platform.environment['LOCALAPPDATA']}\\Programs\\Python\\Python310\\python.exe'
          : '',
      Platform.environment['LOCALAPPDATA'] != null
          ? '${Platform.environment['LOCALAPPDATA']}\\Programs\\Python\\Python39\\python.exe'
          : '',
    ];
    for (final path in commonPaths) {
      if (path.isNotEmpty && File(path).existsSync()) {
        _DebugLog.write('Python found in common path: $path');
        return path;
      }
    }
    _DebugLog.write('Python NOT found by any method!');
    return null;
  }

  Future<_ToolResult> _runProcess(String cmd, List<String> args) async {
    _DebugLog.write('--- _runProcess ---');
    _DebugLog.write('cmd: $cmd');
    _DebugLog.write('args: ${args.join(' ')}');
    try {
      final r = await Process.run(cmd, args,
          stdoutEncoding: utf8, stderrEncoding: utf8);
      final stdoutStr = (r.stdout as String).trim();
      final stderrStr = (r.stderr as String).trim();
      _DebugLog.write('exitCode: ${r.exitCode}');
      _DebugLog.write('stdout (first 500): ${stdoutStr.length > 500 ? stdoutStr.substring(0, 500) : stdoutStr}');
      _DebugLog.write('stderr (first 500): ${stderrStr.length > 500 ? stderrStr.substring(0, 500) : stderrStr}');

      final hasOutput = stdoutStr.isNotEmpty && _looksLikeHashOutput(stdoutStr);
      _DebugLog.write('looksLikeHashOutput: $hasOutput');

      if (r.exitCode != 0 && !hasOutput) {
        String errorMsg = stderrStr;
        if (errorMsg.isEmpty) {
          if (r.exitCode == 9009) {
            errorMsg = '命令未找到 (退出码 9009)：$cmd。请确保 Python 已安装并添加到 PATH。';
          } else {
            errorMsg = '退出码 ${r.exitCode}，无输出';
          }
        }
        _DebugLog.write('FAILED: $errorMsg');
        return _ToolResult(false, stdoutStr, errorMsg);
      }
      _DebugLog.write('SUCCESS');
      return _ToolResult(true, stdoutStr, stderrStr);
    } catch (e, st) {
      _DebugLog.write('EXCEPTION: $e');
      _DebugLog.write('stacktrace: $st');
      return _ToolResult(false, '', '执行失败: $e');
    }
  }

  bool _looksLikeHashOutput(String output) {
    final line = output.trim().split('\n').firstWhere(
          (l) => l.trim().isNotEmpty,
          orElse: () => '',
        );
    if (line.isEmpty) return false;
    // Common hash prefixes
    const prefixes = [
      r'$zip2$',
      r'$pkzip2$',
      r'$pkzip$',
      r'$pdf$',
      r'$office$',
      r'$oldoffice$',
      'WPA*0',
      r'$ml$',
      r'$rar$',
      r'$RAR3$',
      r'$rar5$',
      r'$7z$',
      r'$keepass$',
      r'$bitlocker$',
      r'$luks$',
      r'$truecrypt$',
      r'$veracrypt$',
      r'$bitwarden$',
      r'$metamask$',
      r'$vbox$',
      r'$vmx$',
      r'$vbk$',
      r'$kgb$',
      r'$shiro1$',
      r'$ab$',
      r'$iwork$',
      r'$odf$',
      r'$sshng$',
      r'$ethereum$',
      r'$electrum$',
      r'$bitcoin$',
      'EXODUS:',
      r'$sha1$',
      r'$sha256$',
      r'$sha512$',
      r'$md5$',
      r'$nt$',
    ];
    for (final p in prefixes) {
      if (line.contains(p)) return true;
    }
    // Also check for filename:hash format
    final colonIdx = line.indexOf(':');
    if (colonIdx > 0 && colonIdx < 200) {
      final after = line.substring(colonIdx + 1);
      for (final p in prefixes) {
        if (after.contains(p)) return true;
      }
    }
    return false;
  }

  Future<_ToolResult?> _tryEmbeddedExtractor(
      String name, List<String> args) async {
    return null;
  }

  String _parseHashLine(String output) {
    _DebugLog.write('--- _parseHashLine ---');
    _DebugLog.write('input (first 200): ${output.length > 200 ? output.substring(0, 200) : output}');
    final lines = output.split('\n').where((l) => l.trim().isNotEmpty);
    for (final line in lines) {
      final trimmedLine = line.trim();
      if (trimmedLine.startsWith('Warning') ||
          trimmedLine.startsWith('Using ') ||
          trimmedLine.startsWith('Press ') ||
          trimmedLine.startsWith('HASHCAT_MODE')) {
        continue;
      }
      final firstColonIndex = trimmedLine.indexOf(':');
      String extractedHash;
      if (firstColonIndex != -1 && firstColonIndex < trimmedLine.length - 1) {
        extractedHash = trimmedLine.substring(firstColonIndex + 1);
      } else {
        extractedHash = trimmedLine;
      }
      _DebugLog.write('parsed hash (first 100): ${extractedHash.length > 100 ? extractedHash.substring(0, 100) : extractedHash}');
      return extractedHash;
    }
    _DebugLog.write('No hash line found');
    return '';
  }

  int _pdfHashType(String hash) {
    if (hash.contains('\$pdf\$2*')) return 10600;
    if (hash.contains('\$pdf\$5*')) return 10700;
    if (hash.contains('\$pdf\$4*')) return 10500;
    if (hash.contains('\$pdf\$1*')) return 10400;
    return 10400;
  }

  int _officeHashType(String hash) {
    if (hash.contains('\$oldoffice\$')) {
      if (hash.contains('\$oldoffice\$0\$') ||
          hash.contains('\$oldoffice\$4\$')) return 9700;
      if (hash.contains('\$oldoffice\$1\$') ||
          hash.contains('\$oldoffice\$5\$')) return 9800;
      return 9700;
    }
    if (hash.contains('\$oldoffice\$')) return 9700;
    if (hash.contains('\$office\$')) {
      if (hash.contains('2007')) return 9400;
      if (hash.contains('2010')) return 9500;
      if (hash.contains('2013')) return 9600;
      final parts = hash.split('*');
      if (parts.length > 2) {
        final v = parts[1];
        if (v.contains('2007')) return 9400;
        if (v.contains('2010')) return 9500;
        if (v.contains('2013')) return 9600;
      }
      return 9600;
    }
    return 9600;
  }
}

class _ToolResult {
  final bool success;
  final String stdout;
  final String stderr;
  const _ToolResult(this.success, this.stdout, this.stderr);
}
