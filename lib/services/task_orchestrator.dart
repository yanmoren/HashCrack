import 'dart:async';
import '../models/brute_force.dart';
import '../models/task.dart';
import '../models/file_type.dart';
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

  TaskOrchestrator({
    required this.identifier,
    required this.extractor,
    required this.hashcatFactory,
    required this.dictService,
    required this.workDir,
    this.onUpdated,
  });

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
    if (task != null && !task.status.isTerminal) {
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
