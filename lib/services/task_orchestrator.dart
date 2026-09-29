import 'dart:async';
import '../models/archive_report.dart';
import '../models/brute_force.dart';
import '../models/task.dart';
import '../models/file_type.dart';
import 'archive_auto_extractor.dart';
import 'file_identifier.dart';
import 'extractor_service.dart';
import 'hashcat_service.dart';
import 'dict_service.dart';
import 'package:uuid/uuid.dart';

typedef TaskUpdatedCallback = void Function(CrackTask task);

/// 创建 HashcatService 的工厂。
/// session 即任务 id；onLog / onPhase 用于把运行期状态实时回传到任务对象。
typedef HashcatFactory = HashcatService Function(
  String workDir,
  String session, {
  void Function(String line)? onLog,
  void Function(HashcatPhase phase)? onPhase,
});

class TaskOrchestrator {
  Timer? _debounceTimer;
  static const Duration _debounceDuration = Duration(milliseconds: 50);

  final FileIdentifier identifier;
  final ExtractorService extractor;
  final HashcatFactory hashcatFactory;
  final DictService dictService;
  final String workDir;
  final TaskUpdatedCallback? onUpdated;

  final Map<String, HashcatService> _activeHashcat = {};
  final Map<String, CrackTask> _tasks = {};
  List<CrackTask> _sortedTasks = [];
  final Uuid _uuid = Uuid();

  /// 破解成功后的自动解压。可注入，便于测试不依赖真实 hashcat。
  final ArchiveAutoExtractor autoExtractor;

  TaskOrchestrator({
    required this.identifier,
    required this.extractor,
    required this.hashcatFactory,
    required this.dictService,
    required this.workDir,
    ArchiveAutoExtractor? autoExtractor,
    this.onUpdated,
  }) : autoExtractor = autoExtractor ?? ArchiveAutoExtractor();

  CrackTask? getTask(String id) => _tasks[id];
  List<CrackTask> get allTasks => _sortedTasks;

  Future<CrackTask> submit(String filePath, {String? originalName}) async {
    final id = _newId();
    final name = originalName ?? filePath.split(RegExp(r'[/\\]')).last;
    final task = CrackTask(
      id: id,
      filePath: filePath,
      fileName: name,
      createdAt: DateTime.now(),
    );
    _tasks[id] = task;
    _sortedTasks.add(task);
    _sortedTasks.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    _notify(task);
    unawaited(_run(task));
    return task;
  }

  Future<void> _run(CrackTask task) async {
    try {
      if (!await _identifyFile(task)) return;
      if (!await _extractHash(task)) return;
      if (!await _performCracking(task)) return;

      // 破解成功后的自动解压。放在最后、且自身隔离异常——
      // 密码已经拿到，解压只是把"拿到密码"闭环成"拿到文件"这一步，
      // 任何解压失败都不能反过来把任务标成失败。
      await _extractArchive(task);

      task.finishedAt = DateTime.now();
      _notify(task);
    } catch (e) {
      task.status = TaskStatus.failed;
      task.errorMessage = '异常: $e';
      task.finishedAt = DateTime.now();
      _notify(task);
    }
  }

  Future<bool> _identifyFile(CrackTask task) async {
    task.status = TaskStatus.identifying;
    _notify(task);

    final type = await FileIdentifier.identify(task.filePath);
    task.fileType = type;
    _notify(task);

    if (type == DetectedFileType.unknown) {
      task.status = TaskStatus.failed;
      task.errorMessage = '无法识别文件类型';
      task.finishedAt = DateTime.now();
      _notify(task);
      return false;
    }
    return true;
  }

  Future<bool> _extractHash(CrackTask task) async {
    if (task.fileType == DetectedFileType.hashFile) {
      task.status = TaskStatus.extracting;
      _notify(task);
    } else {
      task.status = TaskStatus.extracting;
      task.currentPhase = TaskPhaseType.extracting;
      _notify(task);
    }

    final extract = await extractor.extract(task.filePath, task.fileType);
    if (!extract.success) {
      task.status = TaskStatus.failed;
      task.errorMessage = extract.error;
      task.finishedAt = DateTime.now();
      _notify(task);
      return false;
    }
    task.hashValue = extract.hash;
    task.hashType = extract.hashType;
    task.hashTypeCandidates = extract.hashTypes;
    task.log += extract.rawOutput;
    _notify(task);
    return true;
  }

  Future<bool> _performCracking(CrackTask task) async {
    HashcatService? hashcat;
    try {
      task.status = TaskStatus.cracking;
      task.currentPhase = TaskPhaseType.dictionaryAttack;
      _notify(task);

      await dictService.ensureBuiltInDict();
      final dicts = await dictService.listDicts();
      final dictPaths = dicts.map((d) => d.path).toList();

      hashcat = hashcatFactory(
        workDir,
        task.id,
        // hashcat 的运行日志必须实时写回任务，否则用户在漫长攻击期间
        // 看到的是一个静止的界面，只能以为软件卡死。
        onLog: (line) => _appendLog(task, line),
        onPhase: (phase) => _updatePhase(task, phase),
      );
      _activeHashcat[task.id] = hashcat;

      final result = await hashcat.run(
        hash: task.hashValue,
        hashType: task.hashType,
        // 结构上符合多个模式时（如 32 位十六进制），字典阶段会按这个顺序
        // 逐个尝试，而不是只赌首选的那一个。
        hashTypes: task.hashTypeCandidates,
        dicts: dictPaths,
        sessionName: task.id,
        // 传原文件用于校验候选密码（ZipCrypto 会产生大量假候选）
        sourceFile: task.filePath,
      );

      _flushLog(task);
      // result.log 与实时日志内容重复，仅在界面日志为空时兜底补上
      if (task.log.trim().isEmpty && result.log.isNotEmpty) {
        task.log = result.log;
      }
      if (result.cracked) {
        task.status = TaskStatus.cracked;
        task.plainPassword = result.password;
        task.progress = 1.0;
      } else {
        task.status = TaskStatus.failed;
        task.errorMessage = result.error;
      }
      _notify(task);
      return result.cracked;
    } finally {
      if (hashcat != null) {
        _activeHashcat.remove(task.id);
      }
    }
  }

  /// 正在解压的任务（用于支持解压中途取消）。
  ///
  /// 不能复用 [cancel] 里那套"改任务状态"的做法：任务此时已经是终态
  /// [TaskStatus.cracked]，改成 cancelled 会把"密码已破出来"这个事实抹掉。
  final Set<String> _cancelExtractRequested = {};

  /// 破解成功后自动解压。
  ///
  /// **整段异常被隔离**：解压只是附加产出，任何失败都只写进
  /// [CrackTask.extractReport]，绝不改变任务状态。用户已经拿到密码了，
  /// 不能因为压缩包太烂就让他以为密码没破出来。
  Future<void> _extractArchive(CrackTask task) async {
    if (task.plainPassword.isEmpty) return;

    if (!ArchiveAutoExtractor.supports(task.fileType)) {
      task.extractReport = ArchiveReport(
        status: ExtractStatus.skipped,
        errorSummary: '该文件类型不参与自动解压',
      );
      _notify(task);
      return;
    }

    task.extractReport = ArchiveReport(status: ExtractStatus.running);
    task.log += '\n\n===== 自动解压：用密码解开压缩包 =====\n';
    _notify(task);

    try {
      final report = await autoExtractor.run(
        archivePath: task.filePath,
        password: task.plainPassword,
        type: task.fileType,
        onUpdate: (r) {
          task.extractReport = r;
          _notify(task);
        },
        isCancelled: () => _cancelExtractRequested.contains(task.id),
      );

      task.extractReport = report;
      _cancelExtractRequested.remove(task.id);

      final r = report.repair;
      if (r != null && r.attempted) {
        task.log += '检测到 ZIP 目录损坏，已重建：救回 ${r.recoveredEntries} 条'
            '${r.succeeded ? "" : "（重建未成功）"}\n';
      }
      task.log += '解压${report.status.label}'
          '${report.outputDir.isEmpty ? "" : "：${report.outputDir}"}\n';
      if (report.errorSummary != null && report.errorSummary!.isNotEmpty) {
        task.log += '说明：${report.errorSummary}\n';
      }
    } catch (e) {
      // 兜底：自动解压组件已自行捕获异常，这里防的是它初始化阶段的问题
      task.extractReport = ArchiveReport(
        status: ExtractStatus.failed,
        errorSummary: '解压过程异常: $e',
      );
      task.log += '解压异常: $e\n';
    }
    _notify(task);
  }

  /// 对一个已经失败（或已取消）的任务重新发起**暴力破解**。
  ///
  /// 复用任务里已经提取好的哈希，不重新识别文件、不重新解析源文件，
  /// 因此对 4.8GB 这种大包也是瞬间开始。
  ///
  /// 之所以做成「用户手动发起」而不是塞进自动流程：暴力破解本质上是在
  /// 赌一个巨大的搜索空间，代价可能是几小时甚至几天。自动跑等于让用户
  /// 在不知情的情况下把电脑押上去，必须由他看过组合空间和预计耗时后点头。
  Future<void> retryWithBruteForce(String taskId, BruteForceConfig config) async {
    final task = _tasks[taskId];
    if (task == null) return;
    if (task.hashValue.isEmpty) return;
    if (task.status.isRunning) return;
    unawaited(_runBruteForce(task, config));
  }

  Future<void> _runBruteForce(CrackTask task, BruteForceConfig config) async {
    HashcatService? hashcat;
    try {
      task.status = TaskStatus.cracking;
      task.currentPhase = TaskPhaseType.bruteForce;
      task.phaseDetail = '暴力破解：${config.label}';
      task.errorMessage = '';
      task.plainPassword = '';
      task.progress = 0;
      task.speedKhs = 0;
      task.etaSeconds = 0;
      task.testedCount = 0;
      task.totalCount = 0;
      task.finishedAt = null;
      task.log += '\n\n===== 手动暴力破解：${config.label} =====\n';
      _notify(task);

      hashcat = hashcatFactory(
        workDir,
        task.id,
        onLog: (line) => _appendLog(task, line),
        onPhase: (phase) => _updatePhase(task, phase),
      );
      _activeHashcat[task.id] = hashcat;

      final result = await hashcat.runBruteForce(
        hash: task.hashValue,
        hashType: task.hashType,
        config: config,
        sessionName: task.id,
        sourceFile: task.filePath,
      );

      _flushLog(task);
      if (task.log.trim().isEmpty && result.log.isNotEmpty) {
        task.log = result.log;
      }
      if (result.cracked) {
        task.status = TaskStatus.cracked;
        task.plainPassword = result.password;
        task.progress = 1.0;
      } else {
        task.status = TaskStatus.failed;
        task.errorMessage =
            result.error.isEmpty ? '暴力破解未命中' : result.error;
      }
      task.finishedAt = DateTime.now();
      _notify(task);
    } catch (e) {
      task.status = TaskStatus.failed;
      task.errorMessage = '暴力破解异常: $e';
      task.finishedAt = DateTime.now();
      _notify(task);
    } finally {
      _activeHashcat.remove(task.id);
    }
  }

  /// 运行日志写入缓冲区，按固定节奏 flush 到任务对象。
  /// 直接每条都触发 UI 刷新会被 hashcat 的高频输出冲垮。
  ///
  /// 缓冲区必须**按任务分开**：多个任务可以同时跑（用户在旧任务上发起
  /// 暴力破解时其它任务还在跑），共用一份 pending 会把 A 的日志写进 B。
  final Map<String, String> _logPendingByTask = {};
  final Map<String, Timer> _logFlushTimers = {};

  void _appendLog(CrackTask task, String line) {
    if (line.trim().isEmpty) return;
    var pending = '${_logPendingByTask[task.id] ?? ''}$line\n';
    if (pending.length > 8000) {
      pending = pending.substring(pending.length - 4000);
    }
    _logPendingByTask[task.id] = pending;
    _logFlushTimers[task.id]?.cancel();
    _logFlushTimers[task.id] = Timer(const Duration(milliseconds: 400), () {
      final p = _logPendingByTask.remove(task.id);
      if (p == null || p.isEmpty) return;
      task.log += p;
      _notify(task);
    });
  }

  void _updatePhase(CrackTask task, HashcatPhase phase) {
    _flushLog(task);
    // 暴力破解必须和「掩码攻击」区分开：前者是用户自己选的策略，
    // 可能不限时地跑很久，界面要给的是「预计多久」而不是「卡住了」。
    task.currentPhase = phase.isBruteForce
        ? TaskPhaseType.bruteForce
        : (phase.isMask ? TaskPhaseType.maskAttack : TaskPhaseType.dictionaryAttack);
    task.phaseDetail = phase.detail;
    // 换阶段意味着上一轮的进度已作废，不清零会显示成「100% 卡住」
    task.progress = 0;
    task.testedCount = 0;
    task.totalCount = 0;
    _notify(task);
  }

  void _flushLog(CrackTask task) {
    _logFlushTimers.remove(task.id)?.cancel();
    final p = _logPendingByTask.remove(task.id);
    if (p != null && p.isNotEmpty) {
      task.log += p;
    }
  }

  void updateProgress(String taskId, HashcatProgress p) {
    final task = _tasks[taskId];
    if (task == null) return;
    task.progress = p.progress;
    task.speedKhs = p.speedKhs;
    task.etaSeconds = p.etaSeconds;
    task.testedCount = p.testedCount;
    task.totalCount = p.totalCount;
    _notify(task);
  }

  void cancel(String taskId) {
    _activeHashcat[taskId]?.cancel();
    final task = _tasks[taskId];
    if (task == null) return;

    // 正在解压时只请求中止解压，**不改任务状态**——此时任务已是
    // "已破解"，把它标成"已取消"等于抹掉密码已破解这个事实。
    final r = task.extractReport;
    if (r != null && r.status == ExtractStatus.running) {
      _cancelExtractRequested.add(taskId);
      return;
    }

    if (!task.status.isTerminal) {
      task.status = TaskStatus.cancelled;
      task.finishedAt = DateTime.now();
      _notify(task);
    }
  }

  void _notify(CrackTask task) {
    _debounceTimer?.cancel();
    _debounceTimer = Timer(_debounceDuration, () {
      onUpdated?.call(task);
    });
  }

  String _newId() => _uuid.v4();
}
