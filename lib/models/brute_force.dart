/// 暴力破解（Brute-force）策略的参数模型。
///
/// 为什么需要它：
/// 原来的策略链只有「字典 → 11 组写死的短掩码」，而且每组掩码都被
/// `--runtime=180` 硬砍 3 分钟。对 WPA 握手包（-m 22000）这种慢哈希，
/// 实测只有几万 H/s，3 分钟连 6 位数字都跑不完就会被截断，
/// 于是界面直接报「所有策略均未命中」——用户既不知道跑了多少，也无法干预。
///
/// 这里把「字符集 + 长度范围」抽象成可配置对象，配合 hashcat 的
/// `--increment`（按长度递增，一次进程内从最短试到最长），
/// 再算出组合空间与预计耗时，让用户自己决定要不要押上几个小时。
library;

/// hashcat 内建字符集的大小。
///
/// - `?d` 数字 0-9（10）
/// - `?l` 小写 a-z（26）
/// - `?u` 大写 A-Z（26）
/// - `?s` 符号（33）
/// - `?a` 全部可见字符（95）
/// - `?h`/`?H` 十六进制小写/大写（16）
/// - `?b` 任意字节（256）
const Map<String, int> kMaskCharsetSizes = {
  '?d': 10,
  '?l': 26,
  '?u': 26,
  '?s': 33,
  '?a': 95,
  '?b': 256,
  '?h': 16,
  '?H': 16,
};

/// 计算一个 hashcat 掩码能生成多少种候选密码。
///
/// 语法规格（与 hashcat 一致）：
/// - `?x` 表示一个字符集占位，例如 `?d` 有 10 种可能
/// - `??` 是转义，表示字面量 `?`，只有 1 种可能
/// - 其它字符都是字面量，只有 1 种可能
///
/// `custom` 用于传入自定义字符集 `?1`~`?4` 的大小。
/// 遇到无法识别的占位符时返回 [BigInt.zero]，表示「未知」，
/// 调用方应当在界面上显示「—」而不是显示一个错误的数字。
BigInt maskKeyspace(String mask, {Map<String, int> custom = const {}}) {
  var total = BigInt.one;
  for (var i = 0; i < mask.length; i++) {
    final c = mask[i];
    if (c != '?') continue; // 字面量，只有 1 种可能
    if (i + 1 >= mask.length) return BigInt.zero;
    final token = mask.substring(i, i + 2);
    i++; // 跳过被占位符消费掉的第二个字符
    if (token == '??') continue; // 转义问号：1 种可能
    final size = kMaskCharsetSizes[token] ?? custom[token];
    if (size == null || size <= 0) return BigInt.zero;
    total *= BigInt.from(size);
  }
  return total;
}

/// 暴力破解使用的字符集预设。
///
/// 多个内建字符集可以拼接，形成「每个位置都有 N 种选择」的口语化字符集，
/// 例如「小写 + 数字」= `?l?d` = 36 种。
///
/// 注意：拼接后的字符集**必须**通过 `-1`（自定义字符集 1）使用，
/// 写成 `?l?d?l?d` 会变成「小写、数字、小写、数字」的交替掩码，语义完全不同。
enum CharsetPreset {
  digits('纯数字', '?d', 10, '0-9'),
  lower('小写字母', '?l', 26, 'a-z'),
  upper('大写字母', '?u', 26, 'A-Z'),
  lowerDigit('小写+数字', '?l?d', 36, 'a-z0-9'),
  upperLowerDigit('大小写+数字', '?u?l?d', 62, 'a-zA-Z0-9'),
  allPrintable('全部可见字符', '?a', 95, '含符号');

  const CharsetPreset(this.label, this.hashcatCharset, this.size, this.sample);

  /// 界面显示名，例如「纯数字」
  final String label;

  /// 传给 hashcat `-1` 参数字符集定义
  final String hashcatCharset;

  /// 每个位置的可选字符数量（用于算组合空间）
  final int size;

  /// 字符范围示例，用于界面副标题
  final String sample;
}

/// 一段暴力破解配置：字符集 + 长度区间 + 是否限时。
class BruteForceConfig {
  /// 每个位置的字符集
  final CharsetPreset charset;

  /// 固定前缀（可选）：一段**字面量**，直接拼在掩码最前面，不参与穷举。
  ///
  /// 为什么需要它：真实世界有大量「固定开头 + 可变尾部」的口令，例如
  /// 运营商生成的 `z` + 9 位数字（真实空间 10^9）。若只用字符集表达，
  /// 得写成 11^10 ≈ 2.6×10^10，比真实空间大 26 倍；把已知的固定开头
  /// 摘出来，代价立刻降回真实规模。没有它，这类口令只能靠外部脚本跑。
  final String prefix;

  /// 起始长度（下限）
  final int minLen;

  /// 最大长度（上限）
  final int maxLen;

  /// 单次运行的时限（秒）。0 表示**不限时**——后台一直跑到命中或穷尽。
  /// WPA 这类慢哈希必须允许不限时，否则任何有意义的长度都跑不完。
  final int runtimeSec;

  const BruteForceConfig({
    required this.charset,
    required this.minLen,
    required this.maxLen,
    this.runtimeSec = 0,
    this.prefix = '',
  });

  /// 生成 hashcat 掩码，例如 maxLen=8 时输出 `?1?1?1?1?1?1?1?1`。
  ///
  /// 统一走 `?1` 而不是直接铺开字符集，是为了让「小写+数字」这类
  /// 多字符集定义在**每一个位置**都生效（`?l?d` 只是两个位置）。
  String get mask => '$_escapedPrefix${List.filled(maxLen, '?1').join()}';

  /// 前缀里的字面量 `?` 必须转义成 `??`。
  ///
  /// 在 hashcat 掩码语法里 `?` 是占位符引导符，前缀写成 `?d` 会被当成
  /// 「一个数字位」而不是两个字符，语义完全不同（且不报错）。
  String get _escapedPrefix => prefix.replaceAll('?', '??');

  /// 总组合空间 = Σ(字符集大小 ^ 长度)，长度从 [minLen] 到 [maxLen]。
  ///
  /// 用 [BigInt] 是因为 8 位全字符已经有 95^8 ≈ 6.6e15，
  /// 10 位纯数字 1e10，都还在 int64 内，但 12 位全字符会溢出——
  /// 暴力破解本来就要往大里算，索性全程用大整数。
  BigInt get keyspace {
    final base = BigInt.from(charset.size);
    var total = BigInt.zero;
    var power = BigInt.one;
    for (var len = 1; len <= maxLen; len++) {
      power *= base;
      if (len >= minLen) total += power;
    }
    return total;
  }

  /// 构造 hashcat 的命令行**选项**部分（不含位置参数）。
  ///
  /// `--increment` 让 hashcat 在一次进程里按长度从 minLen 递增到 maxLen
  /// （长度由短到长，短密码命中概率更高，能更早出结果）；
  /// 相比「为每个长度单独起一次进程」，省掉了重复的初始化与显存分配。
  ///
  /// 注意：掩码是**位置参数**，必须由调用方放在哈希文件之后，
  /// 顺序必须是 `hashcat -m X -a 3 <哈希文件> <掩码> [选项]`。
  /// 如果把掩码放到哈希文件前面，hashcat 会把哈希文件当成「掩码文件」，
  /// 然后报 `Using --custom-charsetX with mask files is misleading` 并直接退出。
  List<String> get optionArgs => [
        '-1', charset.hashcatCharset,
        '--increment',
        // hashcat 把字面前缀也当成掩码的「位置」，而且 --increment 是从
        // **右端**截断的（实测 `z?1?1?1` + --increment-min=3 生成的是
        // `z` + 2 位，而不是把 `z` 丢掉）。所以带前缀时下限必须整体平移
        // 前缀所占的位置数，否则 --increment-min=minLen 会把前缀后面的
        // 可变位截掉一部分，搜出来的东西和配置不符。
        '--increment-min=${_prefixPositions + minLen}',
        '--increment-max=${_prefixPositions + maxLen}',
      ];

  /// 前缀在掩码里占用的「位置」数。
  ///
  /// 用 `prefix.length`（字面量字符数）而不是转义后的长度：hashcat 是把
  /// 掩码解析后再数字符的，`??` 只算一个位置，而它对应的正是前缀里的
  /// 一个 `?`，所以两者一致。
  int get _prefixPositions => prefix.length;

  /// 中文描述，例如「纯数字 6-8 位」或「前缀 z + 纯数字 9 位」。
  String get label {
    final base = minLen == maxLen
        ? '${charset.label} $minLen 位'
        : '${charset.label} $minLen-$maxLen 位';
    return prefix.isEmpty ? base : '前缀 $prefix + $base';
  }

  /// 预计耗时，单位**秒**。`speedPerSec` 为实测速度（次/秒），<= 0 时返回 null 表示未知。
  ///
  /// 注意：这里算的是**跑完整个组合空间**的时间。按期望值，命中密码平均
  /// 只需要遍历空间的一半，但给用户做决策时用悲观值更稳妥。
  ///
  /// ## 为什么返回 BigInt 而不是 Duration（这里踩过一次大坑）
  ///
  /// Dart 的 `Duration` 内部把时长存成 int64 **微秒**，能表示的上限只有
  /// `2^63 / 1e6 ≈ 9.22e12` 秒 ≈ **29.2 万年**。一旦 `Duration(seconds: X)`
  /// 的 X 超过这个值，构造出来的对象**不会报错**，而是按 int64 静默回绕——
  /// 约一半概率变成负数。而 `formatDuration` 见到 `inSeconds <= 0` 就返回
  /// 「不到 1 秒」，于是「大小写+数字 13 位」「全部可见字符 12 位」这类
  /// 需要几百万年的空间，会被显示成 **「不到 1 秒」**。
  ///
  /// 这个错误的**方向极其危险**：它不是保守地高估，而是把最贵的选项
  /// 伪装成最便宜的，会直接诱导用户按下「开始」，然后跑上一辈子。
  ///
  /// 暴力破解的耗时天然横跨 12 个数量级，所以这里全程用大整数秒，
  /// 只在需要给人看的时候才由 `formatSeconds` 做数量级截断。
  BigInt? etaSeconds(int speedPerSec) {
    if (speedPerSec <= 0) return null;
    final ks = keyspace;
    if (ks <= BigInt.zero) return null;
    return ks ~/ BigInt.from(speedPerSec);
  }

  BruteForceConfig copyWith({
    CharsetPreset? charset,
    int? minLen,
    int? maxLen,
    int? runtimeSec,
    String? prefix,
  }) =>
      BruteForceConfig(
        charset: charset ?? this.charset,
        minLen: minLen ?? this.minLen,
        maxLen: maxLen ?? this.maxLen,
        runtimeSec: runtimeSec ?? this.runtimeSec,
        prefix: prefix ?? this.prefix,
      );

  /// 校验并返回修正后的配置：保证 1 <= minLen <= maxLen <= 16，
  /// 前缀最长 32 字符（避免客户端塞一个超长字面量把掩码撐爆）。
  static BruteForceConfig normalized({
    required CharsetPreset charset,
    required int minLen,
    required int maxLen,
    int runtimeSec = 0,
    String prefix = '',
  }) {
    var lo = minLen.clamp(1, 16);
    var hi = maxLen.clamp(1, 16);
    if (hi < lo) {
      final t = lo;
      lo = hi;
      hi = t;
    }
    final cleanPrefix = normalizePrefix(prefix);
    return BruteForceConfig(
      charset: charset,
      minLen: lo,
      maxLen: hi,
      runtimeSec: runtimeSec < 0 ? 0 : runtimeSec,
      prefix: cleanPrefix,
    );
  }

  /// 清理用户输入的前缀：去首尾空白、去掉控制字符、截到 32 字符。
  ///
  /// 允许空格等可打印字符（口令里确实可能有），只挡掉会把命令行/掩码
  /// 搞坏的不可见字符。
  static String normalizePrefix(String raw) {
    final sb = StringBuffer();
    for (final rune in raw.runes) {
      if (rune < 0x20 || rune == 0x7f) continue;
      sb.writeCharCode(rune);
      if (sb.length >= 32) break;
    }
    return sb.toString().trim();
  }
}

/// 按哈希类型给出推荐的暴力破解方案。
///
/// 不同哈希对应完全不同的密码习惯，一刀切没有意义：
/// - WPA 握手包：家用路由器密码受 WPA 规范限制（8-63 位），
///   实际最常见的是 8 位纯数字（手机号后八位）和 8-11 位手机号全号。
/// - 压缩包 / 文档：多为 4-8 位数字或简单字母组合。
///
/// 顺序即推荐优先级，第一个作为默认选中项。
List<BruteForceConfig> recommendedBruteForcePresets(int hashType) {
  if (hashType == 22000) {
    return const [
      // WiFi 密码最短 8 位，8 位纯数字是绝对的多数派
      BruteForceConfig(charset: CharsetPreset.digits, minLen: 8, maxLen: 8),
      // 11 位手机号，以及 9-10 位的变体
      BruteForceConfig(charset: CharsetPreset.digits, minLen: 8, maxLen: 11),
      // 小写 + 数字 8 位（路由器默认密码常见形态）
      BruteForceConfig(charset: CharsetPreset.lowerDigit, minLen: 8, maxLen: 8),
      // 大小写 + 数字 8 位
      BruteForceConfig(
          charset: CharsetPreset.upperLowerDigit, minLen: 8, maxLen: 8),
      // 6 位数字（少数老设备）
      BruteForceConfig(charset: CharsetPreset.digits, minLen: 6, maxLen: 6),
    ];
  }
  return const [
    BruteForceConfig(charset: CharsetPreset.digits, minLen: 1, maxLen: 8),
    BruteForceConfig(charset: CharsetPreset.digits, minLen: 9, maxLen: 10),
    BruteForceConfig(charset: CharsetPreset.lower, minLen: 1, maxLen: 6),
    BruteForceConfig(charset: CharsetPreset.lowerDigit, minLen: 6, maxLen: 8),
    BruteForceConfig(
        charset: CharsetPreset.upperLowerDigit, minLen: 6, maxLen: 8),
  ];
}

/// 把候选数量格式化成中文可读形式（万 / 亿 / 万亿 / 科学计数）。
///
/// 超过 1e16（一万万亿）之后不再硬凑中文单位，改用 `4.4×10³¹` 这种写法。
/// 原因：暴力破解的面板上长度可以拉到 16 位，`95^16 ≈ 4.4e31`，
/// 若继续按「万亿」输出会得到一串 20 位数字，既读不出量级也撑爆布局。
String formatKeyspace(BigInt n) {
  if (n <= BigInt.zero) return '—';
  final thousand = BigInt.from(1000);
  final wan = BigInt.from(10000);
  final yi = BigInt.from(100000000);
  final wanyi = BigInt.from(1000000000000);
  final yiYi = BigInt.from(10000000000000000); // 1e16

  if (n < thousand) return '$n';
  if (n < wan) return '${_trim(n.toDouble() / 1000, 1)} 千';
  if (n < yi) return '${_trim(n.toDouble() / 10000, 1)} 万';
  if (n < wanyi) {
    // 亿这一档跨度很大（1 亿 ~ 9999.99 亿），整数结果直接省略小数，
    // 「100 亿」比「100.00 亿」好读得多
    final v = n.toDouble() / 100000000;
    return '${_trim(v, v >= 100 ? 0 : (v >= 10 ? 1 : 2))} 亿';
  }
  if (n < yiYi) return '${_trim(n.toDouble() / 1000000000000, 2)} 万亿';
  return _scientific(n);
}

/// 把超大整数的量级写成 `4.4×10³¹` 的形式（保留两位有效小数）。
///
/// 直接对 [BigInt] 的十进制字符串取位，不经过浮点，避免 1e31 这类
/// 数值在 double 下丢失精度后输出错误的尾数。
String _scientific(BigInt n) {
  final digits = n.toString();
  final exponent = digits.length - 1;
  final mantissa = digits.length > 1
      ? _trim(double.parse('${digits[0]}.${digits.substring(1)}'), 2)
      : digits;
  return '$mantissa×10${_superscript(exponent)}';
}

const Map<String, String> _kSuperscript = {
  '0': '⁰',
  '1': '¹',
  '2': '²',
  '3': '³',
  '4': '⁴',
  '5': '⁵',
  '6': '⁶',
  '7': '⁷',
  '8': '⁸',
  '9': '⁹',
};

/// 把指数（如 31）转成上标字符串（如 `³¹`）。
String _superscript(int exponent) =>
    exponent.toString().split('').map((c) => _kSuperscript[c] ?? c).join();

/// 按指定小数位格式化并去掉无意义的尾随 0（`1.00` → `1`，`2.50` → `2.5`）。
String _trim(double v, int decimals) {
  var s = v.toStringAsFixed(decimals);
  if (s.contains('.')) {
    s = s.replaceAll(RegExp(r'0+$'), '');
    if (s.endsWith('.')) s = s.substring(0, s.length - 1);
  }
  return s;
}

/// 把**秒数**格式化成中文可读形式。这是耗时的唯一权威格式化入口。
///
/// 暴力破解的预计耗时跨度极大（几秒 ~ 几亿年），必须做数量级截断，
/// 否则界面上会出现「需要 3123456789 秒」这种没法读的数字。
///
/// 参数用 [BigInt] 而不是 `Duration`：`Duration` 只能安全承载到约
/// 29.2 万年，超出会静默回绕成负数，把超长耗时显示成「不到 1 秒」。
/// 详见 [BruteForceConfig.etaSeconds] 的说明。
String formatSeconds(BigInt totalSeconds) {
  if (totalSeconds <= BigInt.zero) return '不到 1 秒';
  final perMinute = BigInt.from(60);
  final perHour = BigInt.from(3600);
  final perDay = BigInt.from(86400);

  if (totalSeconds < perMinute) return '$totalSeconds 秒';
  final minutes = totalSeconds ~/ perMinute;
  if (totalSeconds < perHour) return '$minutes 分';
  final hours = totalSeconds ~/ perHour;
  if (totalSeconds < perDay) {
    final m = minutes % perMinute;
    return m == BigInt.zero ? '$hours 小时' : '$hours 小时 $m 分';
  }
  final days = totalSeconds ~/ perDay;
  if (days < BigInt.from(365)) {
    final h = hours % BigInt.from(24);
    return h == BigInt.zero ? '$days 天' : '$days 天 $h 小时';
  }
  if (days < BigInt.from(36500)) {
    return '${(days.toDouble() / 365).toStringAsFixed(1)} 年';
  }
  if (days < BigInt.from(3650000)) {
    return '${(days.toDouble() / 365).toStringAsFixed(0)} 年';
  }
  return '超过一万年';
}

/// 兼容旧调用：时长本来就用 [Duration] 表示（且保证不超过约 29.2 万年）时走这里。
///
/// 新代码请直接用 [formatSeconds]，不要先把秒数塞进 `Duration`——
/// 对暴力破解这种超大区间，`Duration` 会溢出。
String formatDuration(Duration d) => formatSeconds(BigInt.from(d.inSeconds));
