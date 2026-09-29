class AppConstants {
  static const String appName = 'HashCrack';
  static const String appVersion = '1.0.0';
  static const int defaultServerPort = 8787;

  /// hashcat 可执行文件名
  static const String hashcatExeName = 'hashcat.exe';

  /// 用户未自定义 hashcat 路径时的默认值。
  /// 留空 = 交给 AppPaths 从 runtime/ 目录自动探测，
  /// 绝不写死任何绝对路径，保证软件拷到任何电脑都能跑。
  static const String hashcatDefaultPath = '';

  static const Duration pollInterval = Duration(milliseconds: 500);
  static const Duration statusTimeout = Duration(seconds: 10);

  /// 单次 hashcat 运行的超时上限（防止长任务永久挂起）。
  /// 注意：只有当该阶段设置了 `--runtime` 限时才适用；
  /// 不限时（用户主动发起的暴力破解）会显式传 null 跳过这个上限。
  static const Duration hashcatRunTimeout = Duration(minutes: 30);

  /// 自动流程里单组掩码的默认运行时限（秒）。
  /// 180 秒对弱哈希够用、对 WPA 这种慢哈希远远不够，用户可在设置里放宽。
  static const int defaultMaskRuntimeLimitSec = 180;

  /// 单组掩码运行时限的可选项（秒），0 表示不限时。
  /// 界面与持久化都用这套值，避免出现「设置里选不到已保存的值」。
  static const Map<int, String> maskRuntimeLimitOptions = {
    180: '3 分钟（默认）',
    600: '10 分钟',
    1800: '30 分钟',
    7200: '2 小时',
    0: '不限时（慢哈希推荐）',
  };

  static const Map<String, int> hashTypeMap = {
    'zip': 13600,
    'pdf_104': 10400,
    'pdf_105': 10500,
    'pdf_106': 10600,
    'pdf_107': 10700,
    'office_2007': 9400,
    'office_2010': 9500,
    'office_2013': 9600,
    'office_97_03_word': 9700,
    'office_97_03_excel': 9800,
    'wifi_wpa': 22000,
  };

  static const List<String> supportedExtensions = [
    '.zip', '.pdf', '.doc', '.xls', '.ppt',
    '.docx', '.xlsx', '.pptx', '.cap', '.pcap',
    '.pcapng',
  ];

  /// 把用户填写的 hashcat 路径规整成可执行文件绝对路径。
  /// - 空字符串：交给 AppPaths 自动探测
  /// - 目录：追加 hashcat.exe
  /// - 已经是 .exe：原样返回
  ///
  /// 注意：Windows 和 Linux 的路径分隔符都要考虑，故用 Platform 之外
  /// 的稳妥写法——先判断是否已指向可执行文件。
  static String normalizeHashcatPath(String input) {
    final trimmed = input.trim();
    if (trimmed.isEmpty) return '';
    if (trimmed.toLowerCase().endsWith('.exe') ||
        trimmed.toLowerCase().endsWith('.bin')) {
      return trimmed;
    }
    return '$trimmed\\$hashcatExeName';
  }
}
