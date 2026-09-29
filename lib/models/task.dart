import 'archive_report.dart';
import 'file_type.dart';

enum TaskStatus {
  pending,
  identifying,
  extracting,
  cracking,
  cracked,
  failed,
  cancelled,
}

extension TaskStatusX on TaskStatus {
  String get label {
    switch (this) {
      case TaskStatus.pending:
        return '等待中';
      case TaskStatus.identifying:
        return '识别文件';
      case TaskStatus.extracting:
        return '提取哈希';
      case TaskStatus.cracking:
        return '破解中';
      case TaskStatus.cracked:
        return '已破解';
      case TaskStatus.failed:
        return '失败';
      case TaskStatus.cancelled:
        return '已取消';
    }
  }

  bool get isTerminal =>
      this == TaskStatus.cracked ||
      this == TaskStatus.failed ||
      this == TaskStatus.cancelled;

  bool get isRunning =>
      this == TaskStatus.identifying ||
      this == TaskStatus.extracting ||
      this == TaskStatus.cracking;
}

enum TaskPhaseType {
  none(''),
  identifying('识别文件'),
  extracting('提取哈希'),
  dictionaryAttack('字典攻击'),
  maskAttack('掩码攻击'),
  bruteForce('暴力破解');

  const TaskPhaseType(this.label);
  final String label;
}

class CrackTask {
  final String id;
  final String filePath;
  final String fileName;
  DetectedFileType fileType;
  TaskStatus status;
  String hashValue;
  int hashType;

  /// 候选哈希模式（按常见程度排序）。
  ///
  /// 有些哈希在结构上同时符合多个模式（32 位十六进制可能是 MD5 / NTLM / MD4），
  /// 字典阶段会按这个顺序逐个试，比只赌一个模式命中率高得多。
  List<int> hashTypeCandidates;
  String plainPassword;
  String log;
  double progress;
  String errorMessage;
  TaskPhaseType currentPhase;

  /// 阶段明细，例如「字典 2/3：rockyou.txt」「掩码 4/11：?d?d?d?d」。
  /// 掩码攻击往往比字典慢得多，没有明细用户会以为界面卡死。
  String phaseDetail;
  int speedKhs;
  int etaSeconds;
  int testedCount;
  int totalCount;
  DateTime createdAt;
  DateTime? finishedAt;

  /// 破解成功后的自动解压结果。
  ///
  /// 与 [status] 完全解耦：解压失败不影响任务显示「已破解」——
  /// 密码是对的，解压只是附加产出，不该因为包太烂而让用户以为没破出来。
  ArchiveReport? extractReport;

  CrackTask({
    required this.id,
    required this.filePath,
    required this.fileName,
    this.fileType = DetectedFileType.unknown,
    this.status = TaskStatus.pending,
    this.hashValue = '',
    this.hashType = 0,
    this.hashTypeCandidates = const [],
    this.plainPassword = '',
    this.log = '',
    this.progress = 0,
    this.errorMessage = '',
    this.currentPhase = TaskPhaseType.none,
    this.phaseDetail = '',
    this.speedKhs = 0,
    this.etaSeconds = 0,
    this.testedCount = 0,
    this.totalCount = 0,
    required this.createdAt,
    this.finishedAt,
    this.extractReport,
  });

  Map<String, dynamic> toMap() => {
        'id': id,
        'filePath': filePath,
        'fileName': fileName,
        'fileType': fileType.name,
        'status': status.name,
        'hashValue': hashValue,
        'hashType': hashType,
        'hashTypeCandidates': hashTypeCandidates,
        'plainPassword': plainPassword,
        'progress': progress,
        'errorMessage': errorMessage,
        'currentPhase': currentPhase.name,
        'phaseDetail': phaseDetail,
        'speedKhs': speedKhs,
        'etaSeconds': etaSeconds,
        'createdAt': createdAt.toIso8601String(),
        'finishedAt': finishedAt?.toIso8601String(),
        'extractReport': extractReport?.toJson(),
      };

  factory CrackTask.fromMap(Map<String, dynamic> m) => CrackTask(
        id: m['id'] as String,
        filePath: m['filePath'] as String,
        fileName: m['fileName'] as String,
        fileType: DetectedFileType.values.firstWhere(
          (e) => e.name == m['fileType'],
          orElse: () => DetectedFileType.unknown,
        ),
        status: TaskStatus.values.firstWhere(
          (e) => e.name == m['status'],
          orElse: () => TaskStatus.pending,
        ),
        hashValue: m['hashValue'] as String? ?? '',
        hashType: m['hashType'] as int? ?? 0,
        hashTypeCandidates:
            (m['hashTypeCandidates'] as List?)?.whereType<int>().toList() ??
                const [],
        plainPassword: m['plainPassword'] as String? ?? '',
        progress: (m['progress'] as num?)?.toDouble() ?? 0,
        errorMessage: m['errorMessage'] as String? ?? '',
        currentPhase: TaskPhaseType.values.firstWhere(
          (e) => e.name == m['currentPhase'],
          orElse: () => TaskPhaseType.none,
        ),
        phaseDetail: m['phaseDetail'] as String? ?? '',
        speedKhs: m['speedKhs'] as int? ?? 0,
        etaSeconds: m['etaSeconds'] as int? ?? 0,
        createdAt: DateTime.tryParse(m['createdAt'] as String? ?? '') ??
            DateTime.now(),
        finishedAt: m['finishedAt'] != null
            ? DateTime.tryParse(m['finishedAt'] as String)
            : null,
        extractReport: m['extractReport'] is Map
            ? ArchiveReport.fromJson(
                (m['extractReport'] as Map).cast<String, dynamic>())
            : null,
      );

  String get etaLabel {
    if (etaSeconds <= 0) return '--';
    if (etaSeconds > 86400) {
      final d = (etaSeconds / 86400).ceil();
      return '$d 天';
    }
    if (etaSeconds > 3600) {
      final h = (etaSeconds / 3600).ceil();
      return '$h 时';
    }
    if (etaSeconds > 60) {
      final m = (etaSeconds / 60).ceil();
      return '$m 分';
    }
    return '$etaSeconds 秒';
  }

  String get speedLabel {
    if (speedKhs <= 0) return '--';
    if (speedKhs >= 1000) {
      return '${(speedKhs / 1000).toStringAsFixed(2)} M/s';
    }
    return '$speedKhs k/s';
  }
}
