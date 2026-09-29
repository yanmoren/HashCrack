/// 压缩包解压与修复的结果模型。
///
/// 与 `CrackTask` 的关系：任务破解成功后会多出一个 `extractReport`，
/// 它**完全独立于破解状态**——解压失败不影响任务显示「已破解」。
/// 之所以独立成文件：修复报告、解压报告、失败条目三种数据各有自己的
/// 序列化需求，塞进 task.dart 会让那个文件同时承担两件事。
library;

/// 解压阶段的状态。
///
/// 刻意与 [TaskStatus] 分开：任务是「破解」的进度，这里是「解压」的进度，
/// 两者可以同时处于不同状态（已破解 + 解压失败是合法组合）。
enum ExtractStatus {
  /// 尚未开始
  pending,

  /// 正在解压
  running,

  /// 全部文件解出
  success,

  /// 部分文件解出，其余失败
  partial,

  /// 一个文件都没解出来
  failed,

  /// 该类型不参与解压（如 PDF、Office 文档）
  skipped;

  String get label {
    switch (this) {
      case ExtractStatus.pending:
        return '待解压';
      case ExtractStatus.running:
        return '正在解压';
      case ExtractStatus.success:
        return '解压完成';
      case ExtractStatus.partial:
        return '部分解出';
      case ExtractStatus.failed:
        return '解压失败';
      case ExtractStatus.skipped:
        return '未解压';
    }
  }

  bool get isTerminal => this != ExtractStatus.pending && this != ExtractStatus.running;
}

/// 一个成功解出的文件。
///
/// 只记相对路径与大小：绝对路径包含用户机器上的目录结构，
/// 手机端拿到也没用，反而在序列化时把本地路径泄露到网络上。
class ExtractedFile {
  final String relativePath;
  final int size;

  const ExtractedFile({required this.relativePath, required this.size});

  Map<String, dynamic> toJson() => {
        'relativePath': relativePath,
        'size': size,
      };

  factory ExtractedFile.fromJson(Map<String, dynamic> m) => ExtractedFile(
        relativePath: m['relativePath'] as String? ?? '',
        size: _toInt(m['size']),
      );
}

/// 一个没能解出来的条目。
///
/// [reason] 必须是**具体原因**（如「CRC 校验失败」「密码错误」），
/// 不允许写「未知错误」——用户看到模糊措辞只会以为是软件坏了。
class FailedEntry {
  final String name;
  final String reason;

  const FailedEntry({required this.name, required this.reason});

  Map<String, dynamic> toJson() => {'name': name, 'reason': reason};

  factory FailedEntry.fromJson(Map<String, dynamic> m) => FailedEntry(
        name: m['name'] as String? ?? '',
        reason: m['reason'] as String? ?? '',
      );
}

/// ZIP 结构修复的结果。
///
/// [attempted] 为 false 表示压根没走修复链路（例如包本身是好的，
/// 或类型不是 ZIP），此时其余字段无意义。
class RepairReport {
  /// 是否尝试过修复
  final bool attempted;

  /// 修复是否成功产出了可用的包
  final bool succeeded;

  /// 修复产物路径；受大包阈值控制时可能为 null（修了但不留档）
  final String? repairedPath;

  /// 成功重建的条目数
  final int recoveredEntries;

  /// 扫描到但放弃的条目（结构不可信，救不出来）
  final List<FailedEntry> droppedEntries;

  /// 修复过程本身的错误（与「条目解不出」是两回事）
  final String? error;

  const RepairReport({
    this.attempted = false,
    this.succeeded = false,
    this.repairedPath,
    this.recoveredEntries = 0,
    this.droppedEntries = const [],
    this.error,
  });

  /// 未尝试修复时的空报告
  static const RepairReport notAttempted = RepairReport();

  Map<String, dynamic> toJson() => {
        'attempted': attempted,
        'succeeded': succeeded,
        'repairedPath': repairedPath,
        'recoveredEntries': recoveredEntries,
        'droppedEntries': droppedEntries.map((e) => e.toJson()).toList(),
        'error': error,
      };

  factory RepairReport.fromJson(Map<String, dynamic> m) => RepairReport(
        attempted: m['attempted'] as bool? ?? false,
        succeeded: m['succeeded'] as bool? ?? false,
        repairedPath: m['repairedPath'] as String?,
        recoveredEntries: _toInt(m['recoveredEntries']),
        droppedEntries: ((m['droppedEntries'] as List?) ?? const [])
            .whereType<Map>()
            .map((e) => FailedEntry.fromJson(e.cast<String, dynamic>()))
            .toList(),
        error: m['error'] as String?,
      );
}

/// 一次自动解压的完整结果，挂在 `CrackTask` 上。
class ArchiveReport {
  ExtractStatus status;

  /// 解压输出目录；未解压时为空串
  String outputDir;

  /// 成功解出的文件
  List<ExtractedFile> files;

  /// 未能解出的条目
  List<FailedEntry> failed;

  /// 是否走过 ZIP 修复链路
  RepairReport? repair;

  /// 给用户看的一句话结论；失败时必须有内容
  String? errorSummary;

  /// 0.0 ~ 1.0
  double progress;

  ArchiveReport({
    this.status = ExtractStatus.pending,
    this.outputDir = '',
    List<ExtractedFile>? files,
    List<FailedEntry>? failed,
    this.repair,
    this.errorSummary,
    this.progress = 0,
  })  : files = files ?? <ExtractedFile>[],
        failed = failed ?? <FailedEntry>[];

  /// 解出的总字节数
  int get totalBytes => files.fold(0, (sum, f) => sum + f.size);

  /// 是否走完流程（可据此决定界面显示什么）
  bool get isTerminal => status.isTerminal;

  /// 是否给出了可用的救出结果
  bool get hasUsableOutput => files.isNotEmpty;

  Map<String, dynamic> toJson() => {
        'status': status.name,
        'outputDir': outputDir,
        'files': files.map((f) => f.toJson()).toList(),
        'failed': failed.map((f) => f.toJson()).toList(),
        'repair': repair?.toJson(),
        'errorSummary': errorSummary,
        'progress': progress,
      };

  factory ArchiveReport.fromJson(Map<String, dynamic> m) {
    final repairJson = m['repair'];
    return ArchiveReport(
      status: ExtractStatus.values.firstWhere(
        (s) => s.name == m['status'],
        orElse: () => ExtractStatus.pending,
      ),
      outputDir: m['outputDir'] as String? ?? '',
      files: ((m['files'] as List?) ?? const [])
          .whereType<Map>()
          .map((e) => ExtractedFile.fromJson(e.cast<String, dynamic>()))
          .toList(),
      failed: ((m['failed'] as List?) ?? const [])
          .whereType<Map>()
          .map((e) => FailedEntry.fromJson(e.cast<String, dynamic>()))
          .toList(),
      repair: repairJson is Map
          ? RepairReport.fromJson(repairJson.cast<String, dynamic>())
          : null,
      errorSummary: m['errorSummary'] as String?,
      progress: _toDouble(m['progress']),
    );
  }
}

/// 从可能来自网络的 JSON 里安全取整数。
///
/// 这些字段可能来自手机端提交或旧版本程序，类型未必如预期。
/// 一律降级为默认值而不是抛异常——列表页因为一个字段类型不对而整页崩掉，
/// 比数值不准严重得多。
int _toInt(Object? v) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? 0;
  return 0;
}

/// 安全取浮点数，语义同 [_toInt]。
double _toDouble(Object? v) {
  if (v is double) return v;
  if (v is num) return v.toDouble();
  if (v is String) return double.tryParse(v) ?? 0;
  return 0;
}
