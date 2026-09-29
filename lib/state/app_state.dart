import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/brute_force.dart';
import '../models/task.dart';
import '../services/task_orchestrator.dart';
import '../services/extractor_service.dart';
import '../services/file_identifier.dart';
import '../services/hashcat_service.dart';
import '../services/dict_service.dart';
import '../services/server_service.dart';
import '../services/remote_client.dart';
import '../services/mifare_service.dart';
import '../services/app_paths.dart';
import '../utils/constants.dart';
import '../utils/platform_utils.dart';

class AppState extends ChangeNotifier {
  final bool isPcMode;

  late String workDir;
  late String toolsDir;
  late String uploadDir;
  late String dictsWorkDir;
  late String assetsDictsDir;

  String hashcatPath;
  String userToolsDir;
  String pcHost;
  int pcPort;
  String pythonPath;

  /// 自动流程里「单组掩码」的运行时限（秒）。0 = 不限时。
  ///
  /// 这是「所有策略均未命中」的一个真实成因：原来是写死的 180 秒，
  /// 而 WPA（-m 22000）在普通机器上只有几万 H/s，3 分钟连 8 位数字的零头
  /// 都跑不完。用户可以在这里放宽，让自动流程真正跑完。
  int maskRuntimeLimitSec;

  TaskOrchestrator? orchestrator;
  ServerService? server;
  DictService? dictService;
  RemoteClient? remote;

  /// MIFARE 转储分析与密钥恢复。纯本地计算，双端都能用，不依赖 hashcat。
  final MifareService mifareService = const MifareService();

  List<CrackTask> tasks = [];
  Timer? _pollTimer;
  bool initialized = false;
  String? initError;
  ServerInfo? serverInfo;

  AppState({
    required this.isPcMode,
    this.hashcatPath = AppConstants.hashcatDefaultPath,
    this.userToolsDir = '',
    this.pcHost = '',
    this.pcPort = AppConstants.defaultServerPort,
    this.pythonPath = '',
    this.maskRuntimeLimitSec = AppConstants.defaultMaskRuntimeLimitSec,
  });

  static Future<AppState> create() async {
    final isPc = PlatformUtils.canRunHashcatLocally;
    final prefs = await SharedPreferences.getInstance();
    return AppState(
      isPcMode: isPc,
      hashcatPath: prefs.getString('hashcatPath') ??
          (isPc ? AppConstants.hashcatDefaultPath : ''),
      userToolsDir: prefs.getString('userToolsDir') ?? '',
      pcHost: prefs.getString('pcHost') ?? '',
      pcPort: prefs.getInt('pcPort') ?? AppConstants.defaultServerPort,
      pythonPath: prefs.getString('pythonPath') ?? '',
      maskRuntimeLimitSec: prefs.getInt('maskRuntimeLimitSec') ??
          AppConstants.defaultMaskRuntimeLimitSec,
    ).._init();
  }

  Future<void> _init() async {
    try {
      // 工作目录放在软件自己的 runtime 目录下，而不是 %APPDATA%。
      // 好处：整包可以随意搬移/删除，不会在系统目录里留下残渣，
      // 也彻底摆脱对 path_provider 插件（及其引出的 iOS/macOS 依赖链）的需要。
      if (AppPaths.isAvailable) {
        workDir = '${AppPaths.runtimeRoot}${Platform.pathSeparator}work';
      } else {
        workDir =
            '${Directory.systemTemp.path}${Platform.pathSeparator}hashcrack';
      }
      await Directory(workDir).create(recursive: true);
      toolsDir = '$workDir${Platform.pathSeparator}tools';
      uploadDir = '$workDir${Platform.pathSeparator}uploads';
      dictsWorkDir = '$workDir${Platform.pathSeparator}dicts';
      await Directory(toolsDir).create(recursive: true);
      await Directory(uploadDir).create(recursive: true);
      await Directory(dictsWorkDir).create(recursive: true);

      if (isPcMode) {
        await _initPcMode();
      } else {
        await _initMobileMode();
      }
      initialized = true;
      notifyListeners();
    } catch (e) {
      initError = '初始化失败: $e';
      initialized = true;
      notifyListeners();
    }
  }

  Future<void> _initPcMode() async {
    // 提取工具和字典都直接读 runtime/ 目录，不再从 Flutter assets 里释放，
    // 这样用户可以随时往 runtime\dicts 里丢自己的字典，软件重启即生效。
    assetsDictsDir = AppPaths.dictsDir;

    // 字典目录不存在时兜底创建一个，避免首次运行报错
    if (AppPaths.dictsDir.isNotEmpty) {
      await Directory(AppPaths.dictsDir).create(recursive: true);
    }

    // Resolve hashcat directory for dict service
    final resolvedHashcat = _resolveHashcatPath();
    final hashcatDir = resolvedHashcat.isNotEmpty
        ? File(resolvedHashcat).parent.path
        : null;

    dictService = DictService(
      workDir: workDir,
      assetsDictsDir: assetsDictsDir,
      hashcatDir: hashcatDir,
      portableDictsDir: AppPaths.dictsDir,
    );

    final extractor = ExtractorService(
      toolsDir: effectiveToolsDir,
      pythonPath: pythonPath.isNotEmpty ? pythonPath : AppPaths.pythonExe,
      onLog: (l) => debugPrint('[extractor] $l'),
    );

    final hashcatPathResolved = _resolveHashcatPath();

    late TaskOrchestrator orch;
    orch = TaskOrchestrator(
      identifier: FileIdentifier(),
      extractor: extractor,
      dictService: dictService!,
      workDir: workDir,
      onUpdated: (task) => _onTaskUpdated(task),
      hashcatFactory: (wd, session, {onLog, onPhase}) => HashcatService(
        hashcatPath: hashcatPathResolved,
        workDir: wd,
        pythonPath: AppPaths.pythonExe,
        onProgress: (p) => orch.updateProgress(session, p),
        onLog: onLog,
        onPhase: onPhase,
        maskRuntimeLimitSec: maskRuntimeLimitSec,
      ),
    );
    orchestrator = orch;
    _syncTasks();

    server = ServerService(
      orchestrator: orch,
      dictService: dictService!,
      port: pcPort,
      uploadDir: uploadDir,
      hashcatPath: hashcatPathResolved,
    );
    try {
      serverInfo = await server!.start();
    } catch (e) {
      initError = 'HTTP 服务启动失败: $e';
    }
  }

  Future<void> _initMobileMode() async {
    remote = RemoteClient(host: pcHost, port: pcPort);
    if (remote!.isConfigured) {
      await refreshTasks();
    }
    _startPolling();
  }

  /// 解析 hashcat 可执行文件路径。
  ///
  /// 优先级：用户在设置里指定的路径 → 软件自带的 runtime/hashcat。
  /// 全路径相对解析，不含任何写死的绝对路径，保证换机可用。
  String _resolveHashcatPath() {
    // 1) 用户显式配置
    if (hashcatPath.isNotEmpty) {
      final normalized = AppConstants.normalizeHashcatPath(hashcatPath);
      if (File(normalized).existsSync()) {
        return File(normalized).absolute.path;
      }
    }

    // 2) 软件自带内核（runtime/hashcat）
    final bundled = AppPaths.hashcatExe;
    if (bundled.isNotEmpty && File(bundled).existsSync()) {
      return File(bundled).absolute.path;
    }

    // 3) 用户自定义工具目录里找
    if (userToolsDir.isNotEmpty) {
      for (final c in [
        '$userToolsDir${Platform.pathSeparator}hashcat${Platform.pathSeparator}${AppConstants.hashcatExeName}',
        '$userToolsDir${Platform.pathSeparator}${AppConstants.hashcatExeName}',
      ]) {
        if (File(c).existsSync()) return File(c).absolute.path;
      }
    }

    // 4) 系统 PATH 兜底
    if (PlatformUtils.isWindows) {
      try {
        final r = Process.runSync('where', [AppConstants.hashcatExeName]);
        if (r.exitCode == 0) {
          final path = (r.stdout as String).trim().split('\n').first.trim();
          if (path.isNotEmpty && File(path).existsSync()) {
            return File(path).absolute.path;
          }
        }
      } catch (_) {}
    } else {
      for (final c in ['hashcat', '/usr/bin/hashcat', '/usr/local/bin/hashcat']) {
        if (File(c).existsSync()) return File(c).absolute.path;
      }
    }

    return hashcatPath.isNotEmpty
        ? AppConstants.normalizeHashcatPath(hashcatPath)
        : AppConstants.hashcatDefaultPath;
  }

  /// 哈希提取工具目录（优先用户自定义，否则用自带的 runtime/tools）
  String get effectiveToolsDir =>
      userToolsDir.isNotEmpty ? userToolsDir : AppPaths.toolsDir;

  /// 环境自检报告（供设置页展示）
  String get environmentReport => AppPaths.describe();

  void _onTaskUpdated(CrackTask task) {
    final idx = tasks.indexWhere((t) => t.id == task.id);
    if (idx >= 0) {
      tasks[idx] = task;
    } else {
      tasks.insert(0, task);
    }
    notifyListeners();
  }

  void _syncTasks() {
    if (orchestrator != null) {
      tasks = orchestrator!.allTasks;
      notifyListeners();
    }
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(AppConstants.pollInterval, (_) {
      refreshTasks();
    });
  }

  Future<void> refreshTasks() async {
    if (isPcMode) {
      _syncTasks();
      return;
    }
    if (remote == null || !remote!.isConfigured) return;
    try {
      tasks = await remote!.getTasks();
      notifyListeners();
    } catch (_) {}
  }

  Future<CrackTask?> submitLocalFile(String path) async {
    if (!isPcMode || orchestrator == null) return null;
    final name = path.split(RegExp(r'[/\\]')).last;
    final task = await orchestrator!.submit(path, originalName: name);
    _syncTasks();
    return task;
  }

  Future<String?> submitRemoteFile(String path) async {
    if (remote == null || !remote!.isConfigured) {
      throw Exception('未配置 PC 地址');
    }
    final id = await remote!.uploadFile(path);
    await refreshTasks();
    return id;
  }

  Future<void> cancelTask(String id) async {
    if (isPcMode) {
      orchestrator?.cancel(id);
      _syncTasks();
    } else {
      await remote?.cancel(id);
      await refreshTasks();
    }
  }

  /// 对已失败（或已取消）的任务重新发起暴力破解。
  /// PC 端本地执行；手机端把参数转给 PC 由 PC 执行。
  Future<void> retryWithBruteForce(
      String taskId, BruteForceConfig config) async {
    if (isPcMode) {
      orchestrator?.retryWithBruteForce(taskId, config);
      _syncTasks();
    } else {
      await remote?.retryWithBruteForce(taskId, config);
      await refreshTasks();
    }
  }

  /// 修改自动流程里单组掩码的运行时限（秒），0 = 不限时。
  Future<void> setMaskRuntimeLimit(int seconds) async {
    maskRuntimeLimitSec = seconds;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt('maskRuntimeLimitSec', seconds);
    notifyListeners();
  }

  Future<bool> testRemoteConnection() async {
    if (remote == null) return false;
    return remote!.ping();
  }

  Future<void> setRemoteConfig(String host, int port) async {
    pcHost = host;
    pcPort = port;
    remote?.configure(host, port);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('pcHost', host);
    await prefs.setInt('pcPort', port);
    notifyListeners();
  }

  Future<void> setHashcatPath(String path) async {
    hashcatPath = path;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('hashcatPath', path);
    notifyListeners();
  }

  Future<void> setToolsDir(String path) async {
    userToolsDir = path;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('userToolsDir', path);
    notifyListeners();
  }

  Future<void> addDict(String path) async {
    dictService?.addUserDict(path);
    notifyListeners();
  }

  String get effectiveHashcatPath =>
      isPcMode ? _resolveHashcatPath() : hashcatPath;

  String? get localServerError => initError;

  @override
  void dispose() {
    _pollTimer?.cancel();
    server?.stop();
    super.dispose();
  }
}
