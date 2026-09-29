import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:shared_preferences/shared_preferences.dart';

/// 离线授权核心：机器码采集 + HMAC 签名的激活码生成/校验。
///
/// 授权模型（每台机器一个码，离线）：
///   机器码 = 从硬件标识计算出的 5 字节指纹，展示给用户抄给卖家
///   激活码 = base32( 机器ID(5B) + 用途(1B) + HMACSHA256 签名(9B) )
///   校验   = 本机重算 HMAC 并比对机器 ID，纯离线完成
///
/// 安全边界：任何"离线授权"终归敌不过逆向提取内置密钥，本实现只能挡住
/// 普通用户手工拼码/一码多机，防不了专业人士反编译。要更强需上服务端。
class LicenseService {
  LicenseService._();
  static final LicenseService instance = LicenseService._();

  static const int purpose = 0x21; // HashCrack 产品用途字节
  static const int _machineBytes = 5;
  static const int _sigBytes = 9;

  // 主密钥（keygen.py 必须一致）。
  // 轻量异或混淆，防止在二进制里字符串直搜；拿到它即可给任意机器发码，
  // 务必只留给自己。要真正保密需要内置私钥+服务端，纯离线无法做到。
  static List<int> get secret => _xor([
        0x3d, 0xc4, 0x6b, 0xa1, 0x1e, 0x90, 0x27, 0xdf,
        0x58, 0x4c, 0x13, 0xb6, 0xe2, 0x20, 0x78, 0xc9,
      ], 0x5a);

  static List<int> _xor(List<int> d, int k) =>
      [for (final b in d) b ^ k];

  static const String _storeKey = 'hc_license_code';
  static const String _machineKey = 'hc_machine_hex';

  String? _machineHex;
  String? _currentCode;

  /// 机器码十六进制（小写）。未初始化时返回空串。
  String get machineHex => _machineHex ?? '';

  /// 已保存的激活码（未初始化/未激活时可能为空）。
  String? get currentCode => _currentCode;

  /// 是否已激活
  bool get isActivated => _currentCode != null && _currentCode!.isNotEmpty;

  /// 带连字符的展示形态，例如 `ABCDE-FGHIJ`
  String get displayMachineCode {
    final h = machineHex;
    if (h.length < 10) return '';
    return '${h.substring(0, 5).toUpperCase()}-${h.substring(5).toUpperCase()}';
  }

  /// 初始化：采集机器码，读取已保存激活码并校验。
  /// 返回错误信息；返回 null 表示正常（不一定已激活）。
  Future<String?> init() async {
    final prefs = await SharedPreferences.getInstance();
    final hex = await computeMachineHex();
    if (hex.isEmpty) return '无法采集本机机器码';
    _machineHex = hex;
    _currentCode = prefs.getString(_storeKey);
    final savedMachine = prefs.getString(_machineKey);
    if (savedMachine != null && savedMachine.toLowerCase() != hex) {
      // 机器码变了（换硬件/换系统），旧激活码作废
      _currentCode = null;
    }
    if (_currentCode != null) {
      final err = validateActivationCode(_currentCode!, hex);
      if (err != null) _currentCode = null;
      // 若只是"与本机不匹配"仍返回 null，让 UI 展示状态即可
    }
    return null;
  }

  /// 采集本机机器码十六进制。返回空串表示采集失败。
  Future<String> computeMachineHex() async {
    final source = await _collectSource();
    if (source.isEmpty) return '';
    final full = sha256.convert(utf8.encode(source)).bytes;
    final id = List<int>.from(full.sublist(0, _machineBytes));
    return _hex(id);
  }

  Future<String> _collectSource() async {
    if (kIsWeb) return '';
    if (Platform.isAndroid) return _androidSource();
    if (Platform.isWindows) return _windowsSource();
    return 'dev|${Platform.localHostname}';
  }

  Future<String> _androidSource() async {
    try {
      final a = await DeviceInfoPlugin().androidInfo;
      return [
        a.brand,
        a.device,
        a.board,
        a.hardware,
        a.product,
        a.fingerprint,
        a.model,
        a.id,
      ].where((s) => s.isNotEmpty).join('|');
    } catch (_) {
      return '';
    }
  }

  static const String _psScript = '''
\$parts = @()
foreach (\$q in @(
  'Win32_ComputerSystemProduct|UUID',
  'Win32_ComputerSystemProduct|SerialNumber',
  'Win32_BaseBoard|SerialNumber',
  'Win32_Processor|ProcessorId',
  'Win32_LogicalDisk|VolumeSerialNumber'
)) {
  \$cls,\$prop = \$q -split '\|'
  try {
    if (\$cls -eq 'Win32_LogicalDisk') {
      \$v = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").\$prop
    } else {
      \$v = Get-CimInstance \$cls | Select-Object -First 1 -ExpandProperty \$prop
    }
    if (\$v) { \$parts += \$v }
  } catch {}
}
\$parts += "hn:\$env:COMPUTERNAME"
\$parts -join ';'
''';

  Future<String> _windowsSource() async {
    try {
      final r = await Process.run(
        'powershell',
        [
          '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
          '-Command', _psScript,
        ],
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
      );
      if (r.exitCode != 0) return '';
      return (r.stdout as String).trim();
    } catch (_) {
      return '';
    }
  }

  /// 校验激活码是否匹配 + 是否为有效签名。返回 null = 通过。
  String? validateActivationCode(String code, String machineHex) {
    String norm;
    try {
      norm = code.replaceAll(RegExp(r'[^A-Za-z0-9]'), '').toUpperCase();
      if (norm.length != _b32Len) throw const FormatException();
    } catch (_) {
      return '激活码格式不正确';
    }
    Uint8List raw;
    try {
      raw = _b32Decode(norm);
    } catch (_) {
      return '激活码格式不正确';
    }
    if (raw.length != _machineBytes + 1 + _sigBytes) {
      return '激活码无效';
    }
    final machine = raw.sublist(0, _machineBytes);
    final purposeOk = raw[_machineBytes] == purpose;
    final sig = raw.sublist(_machineBytes + 1);
    final expect = _hmac([...machine, purpose]);
    var diff = 0;
    for (var i = 0; i < sig.length; i++) {
      diff |= sig[i] ^ expect[i];
    }
    if (diff != 0) return '激活码签名校验失败';

    final local = _hexToBytes(machineHex);
    if (local.length != _machineBytes || !purposeOk) {
      return '激活码与本机不匹配';
    }
    var mdiff = 0;
    for (var i = 0; i < machine.length; i++) {
      mdiff |= machine[i] ^ local[i];
    }
    if (mdiff != 0) return '激活码与本机不匹配';
    return null;
  }

  /// 用激活码激活本机。返回 null = 成功。
  Future<String?> activate(String code) async {
    final hex = machineHex.isEmpty ? await computeMachineHex() : machineHex;
    if (hex.isEmpty) return '无法采集本机机器码';
    final err = validateActivationCode(code, hex);
    if (err != null) return err;
    final prefs = await SharedPreferences.getInstance();
    final norm = code.replaceAll(RegExp(r'[^A-Za-z0-9]'), '').toUpperCase();
    await prefs.setString(_storeKey, norm);
    await prefs.setString(_machineKey, hex);
    _currentCode = norm;
    return null;
  }

  /// 构造激活码内部负载（供 keygen / 测试用；客户端不直接调用）。
  static String buildActivationCodeBytes(String machineHex, {List<int>? key}) {
    final m = _hexToBytes(machineHex);
    final payload = <int>[...m.sublist(0, _machineBytes), purpose];
    final h = Hmac(sha256, key ?? secret).convert(payload).bytes;
    final raw = <int>[...payload, ...h.sublist(0, _sigBytes)];
    return _b32Encode(Uint8List.fromList(raw));
  }

  /// 以 6 位连字符分组返回激活码（4 组）。
  static String formatActivationCode(String raw) {
    if (raw.length % 6 != 0) return raw;
    final g = <String>[];
    for (var i = 0; i < raw.length; i += 6) {
      g.add(raw.substring(i, i + 6));
    }
    return g.join('-');
  }

  static int get _b32Len {
    final rawLen = _machineBytes + 1 + _sigBytes; // 15
    return (rawLen * 8 + 4) ~/ 5; // 24
  }

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  static List<int> _hexToBytes(String s) {
    final out = <int>[];
    for (var i = 0; i + 1 < s.length; i += 2) {
      out.add(int.parse(s.substring(i, i + 2), radix: 16));
    }
    return out;
  }

  List<int> _hmac(List<int> data) {
    final h = Hmac(sha256, secret).convert(data).bytes;
    return List<int>.from(h.sublist(0, _sigBytes));
  }

  static const String _b32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  static String _b32Encode(Uint8List data) {
    final bits = <int>[];
    for (final byte in data) {
      for (var i = 7; i >= 0; i--) {
        bits.add((byte >> i) & 1);
      }
    }
    final buf = StringBuffer();
    for (var i = 0; i + 5 <= bits.length; i += 5) {
      var v = 0;
      for (var j = 0; j < 5; j++) {
        v = (v << 1) | bits[i + j];
      }
      buf.write(_b32Alphabet[v]);
    }
    return buf.toString();
  }

  static Uint8List _b32Decode(String s) {
    final out = <int>[];
    var acc = 0, bits = 0;
    for (final c in s.split('')) {
      final v = _b32Alphabet.indexOf(c);
      if (v < 0) throw FormatException('bad char');
      acc = (acc << 5) | v;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.add((acc >> bits) & 0xff);
      }
    }
    return Uint8List.fromList(out);
  }
}