import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../models/file_type.dart';
import '../models/file_signatures.dart';
import '../models/mifare.dart';

/// 文件类型识别。
///
/// 判定顺序是分层的，从最可靠到最宽松：
///   1. MIFARE 相关（必须在哈希文本判定之前，见下方注释）
///   2. 文件名特判（key3.db / wallet.dat / CacheData / seco / UTC--… / .encfs6.xml）
///   3. 文件头魔数（注册表里的 [MagicRule]，含偏移与尾部匹配）
///   4. ZIP 容器内的目录结构（区分 Office 新版 / ODF / iWork / 普通 ZIP）
///   5. 文本内容探针（PEM 私钥、PGP armor、各类钱包 JSON、SQLite 库）
///   6. 扩展名兜底（魔数随机或缺失的格式，如 VeraCrypt/TrueCrypt）
///   7. 哈希文本判定
///
/// 之所以要层层递进而不是「看扩展名就完事」：用户拿到的转储/镜像经常被
/// 改名（`.bin`、`.img`、`.dat` 到处都是），扩展名是最不可靠的信号。
class FileIdentifier {
  /// 读取的文件头长度。要覆盖 APFS 那种「魔数在偏移 32」的格式，
  /// 16 字节不够，取 64 字节余量充足。
  static const int _headerLen = 64;

  /// 文件尾读取长度（DMG 的 `koly` 标记在最后 512 字节处）
  static const int _tailLen = 512;

  static Future<DetectedFileType> identify(String path) async {
    final file = File(path);
    if (!await file.exists()) return DetectedFileType.unknown;

    // ── 1) MIFARE 相关必须排在最前 ────────────────────────────────
    // mfkey32 的 nonce 日志里写着 `nt0: 240BD022` 这样的行，形态和
    // `用户名:哈希` 的哈希文件一模一样；放在后面会被哈希判定先抢走。
    if (await looksLikeNonceLog(path)) return DetectedFileType.nonceLog;
    if (await looksLikeMifareDump(path)) return DetectedFileType.mifareDump;

    // ── 2) 文件名特判 ────────────────────────────────────────────
    final byName = _byFileName(path);
    if (byName != null) return byName;

    // ── 3~5) 读头尾 + 魔数 + 结构 + 内容 ─────────────────────────
    final header = await _readHeader(file, _headerLen);
    if (header.length >= 4) {
      // DMG 的标记在尾部，单独拿一次
      final magicHit = await _matchMagic(header, file);
      if (magicHit != null) return magicHit;

      if (_isZip(header)) {
        final zipType = await _classifyZip(path);
        if (zipType != null) return zipType;
      }

      final probed = await _probeContent(path, header);
      if (probed != null) return probed;
    }

    // ── 6) 扩展名兜底 ────────────────────────────────────────────
    final ext = _extensionOf(path);
    if (ext.isNotEmpty) {
      for (final sig in FileSignatures.extensionOnly) {
        if (sig.extensions.contains(ext)) return sig.type;
      }
    }

    // ── 7) 哈希文本 ──────────────────────────────────────────────
    if (ext == 'hash' || ext == 'hsh' || ext == 'txt') {
      final type = await _tryHashFile(path);
      if (type != DetectedFileType.unknown) return type;
    }

    return DetectedFileType.unknown;
  }

  // ══════════════════ 文件名特判 ══════════════════

  /// 有些格式的魔数是「通用容器」（Berkeley DB、纯文本 XML、无魔数），
  /// 光看文件头会把不同的东西混为一谈，只能结合文件名判断。
  static DetectedFileType? _byFileName(String path) {
    final name = path.split(RegExp(r'[/\\]')).last.toLowerCase();

    // Firefox 的密码库：key3.db 是 Berkeley DB，key4.db 是 SQLite
    if (name == 'key3.db' || name == 'key4.db') {
      return DetectedFileType.mozillaKeyDb;
    }
    // Bitcoin Core 钱包：同样是 Berkeley DB
    if (name == 'wallet.dat') return DetectedFileType.bitcoinWallet;
    // Windows 账户缓存，没有魔数
    if (name == 'cachedata') return DetectedFileType.windowsCacheData;
    // Exodus 的种子文件固定叫 seco
    if (name == 'seco' || name.endsWith('.seco')) {
      return DetectedFileType.exodus;
    }
    // EncFS 的配置文件名固定
    if (name.endsWith('.encfs6.xml') || name == '.encfs6.xml') {
      return DetectedFileType.encfs;
    }
    // Ethereum keystore 的标准命名：UTC--<时间>--<地址>
    if (name.startsWith('utc--') && name.endsWith('.json')) {
      return DetectedFileType.ethereumWallet;
    }
    return null;
  }

  // ══════════════════ 魔数匹配 ══════════════════

  static Future<DetectedFileType?> _matchMagic(
      Uint8List header, File file) async {
    Uint8List? tail;
    for (final sig in FileSignatures.magicMatchable) {
      for (final rule in sig.magics) {
        if (!rule.fromEnd) {
          if (_matchAt(header, rule.offset, rule.bytes)) return sig.type;
        } else {
          // 尾部匹配：只在真的有这种规则时才去读文件尾，避免无谓 I/O
          tail ??= await _readTail(file, _tailLen);
          if (tail != null && _matchAt(tail, rule.offset, rule.bytes)) {
            return sig.type;
          }
        }
      }
    }
    return null;
  }

  static bool _matchAt(List<int> data, int offset, List<int> magic) {
    if (offset < 0 || data.length < offset + magic.length) return false;
    for (var i = 0; i < magic.length; i++) {
      if (data[offset + i] != magic[i]) return false;
    }
    return true;
  }

  static bool _isZip(Uint8List h) =>
      _matchAt(h, 0, const [0x50, 0x4B, 0x03, 0x04]) ||
      _matchAt(h, 0, const [0x50, 0x4B, 0x05, 0x06]) ||
      _matchAt(h, 0, const [0x50, 0x4B, 0x07, 0x08]);

  // ══════════════════ ZIP 家族细分 ══════════════════

  /// 列出压缩包内条目。返回 null 表示读不出来（工具缺失/文件损坏）。
  static Future<String?> _zipListing(String path) async {
    try {
      final result = await Process.run(
        Platform.isWindows ? 'tar' : 'unzip',
        Platform.isWindows ? ['-tf', path] : ['-l', path],
        stdoutEncoding: null,
        stderrEncoding: null,
      );
      if (result.exitCode != 0) return null;
      return String.fromCharCodes(result.stdout as List<int>).toLowerCase();
    } catch (_) {
      return null;
    }
  }

  /// 区分 Office 新版 / OpenDocument / iWork / 普通 ZIP。
  ///
  /// 光靠扩展名不可靠：.docx 被改名成 .zip 很常见，反过来也有把普通压缩包
  /// 命名成 .docx 的情况，所以一律以包内结构为准。
  static Future<DetectedFileType?> _classifyZip(String path) async {
    final listing = await _zipListing(path);
    if (listing == null) return DetectedFileType.zip;

    // Office 2007+：OOXML 三件套之一
    if (listing.contains('word/document.xml') ||
        listing.contains('xl/workbook.xml') ||
        listing.contains('ppt/presentation.xml') ||
        listing.contains('[content_types].xml')) {
      return DetectedFileType.officeNew;
    }

    // OpenDocument：mimetype + META-INF/manifest.xml 是固定搭配
    if (listing.contains('meta-inf/manifest.xml') ||
        listing.contains('content.xml')) {
      return DetectedFileType.openDocument;
    }

    // iWork：Index/ + Metadata/ 两个目录同时存在
    if (listing.contains('index/') && listing.contains('metadata/')) {
      return DetectedFileType.iwork;
    }

    return DetectedFileType.zip;
  }

  // ══════════════════ 文本 / 结构内容探针 ══════════════════

  static Future<DetectedFileType?> _probeContent(
      String path, Uint8List header) async {
    // SQLite 头：Chrome 登录库、Firefox key4.db、Apple 钥匙串都是 SQLite。
    // 这些需要看文件名/表结构才能细分，这里先交给文件名特判处理，
    // 没命中文件名特判的按扩展名兜底。
    if (_matchAt(header, 0, const [
      0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
      0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00, //
    ])) {
      final ext = _extensionOf(path);
      if (ext == 'keychain' || ext == 'keychain-db') {
        return DetectedFileType.appleKeychain;
      }
    }

    // 只有看起来像文本才继续做文本探针，避免把二进制文件整块读进来
    if (!_looksLikeText(header)) return null;

    String text;
    try {
      // 只读前 8KB：判断类型足够了，也不会因为一个巨大文件卡住
      final raf = await File(path).open();
      try {
        final bytes = await raf.read(8192);
        text = utf8.decode(bytes, allowMalformed: true);
      } finally {
        await raf.close();
      }
    } catch (_) {
      return null;
    }

    final head = text.trimLeft();

    // OpenSSH / PEM 私钥。注意：PGP armor 里也含 "PRIVATE KEY"，必须先判 PGP。
    if (head.startsWith('-----BEGIN')) {
      if (head.contains('PGP PRIVATE KEY') ||
          head.contains('PGP MESSAGE') ||
          head.contains('PGP SIGNATURE')) {
        return DetectedFileType.pgpKey;
      }
      if (head.contains('PRIVATE KEY')) return DetectedFileType.sshKey;
      // 加密的 PEM（-----BEGIN ENCRYPTED PRIVATE KEY-----）也算私钥
      if (head.contains('ENCRYPTED')) return DetectedFileType.sshKey;
    }
    // PuTTY 私钥
    if (head.startsWith('PuTTY-User-Key-File')) return DetectedFileType.sshKey;

    // JSON 类钱包 / 保险库
    if (head.startsWith('{') || head.startsWith('[')) {
      final lower = text.toLowerCase();
      // Ethereum keystore：crypto + cipher + kdf
      if (lower.contains('"crypto"') &&
          (lower.contains('"scrypt"') || lower.contains('"pbkdf2"') ||
              lower.contains('aes-128-ctr'))) {
        return DetectedFileType.ethereumWallet;
      }
      // MetaMask 保险库：data + iv + salt
      if (lower.contains('"vault"') ||
          (lower.contains('"data"') &&
              lower.contains('"iv"') &&
              lower.contains('"salt"'))) {
        return DetectedFileType.metamask;
      }
      // Electrum 钱包
      if (lower.contains('"seed_version"') || lower.contains('"keystore"')) {
        return DetectedFileType.electrumWallet;
      }
    }

    // VMware VMX 是纯文本配置，靠关键字段识别
    if (text.contains('encryption.keySafe') && text.contains('.encoding')) {
      return DetectedFileType.vmwareVmx;
    }

    // VirtualBox 项目文件是 XML，加密磁盘才有 CRYPT/KeyStore
    if (head.startsWith('<?xml') && text.contains('CRYPT/KeyStore')) {
      return DetectedFileType.virtualboxVdi;
    }

    return null;
  }

  static bool _looksLikeText(Uint8List h) {
    if (h.isEmpty) return false;
    // UTF-8 BOM
    if (h.length >= 3 && h[0] == 0xEF && h[1] == 0xBB && h[2] == 0xBF) {
      return true;
    }
    var printable = 0;
    final n = h.length < 32 ? h.length : 32;
    for (var i = 0; i < n; i++) {
      final b = h[i];
      if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b < 0x7F)) {
        printable++;
      } else if (b == 0x00) {
        return false; // 出现 NUL 基本可判定是二进制
      }
    }
    return printable >= n - 1;
  }

  // ══════════════════ 哈希文本判定 ══════════════════

  /// 兜底的哈希文本判定。
  ///
  /// 只做「是不是哈希文本」的粗判——具体是哪种哈希由 HashIdentifier
  /// （调用 hashcat --identify）决定，这里不重复造轮子。
  static Future<DetectedFileType> _tryHashFile(String path) async {
    try {
      final content = await File(path).readAsString();
      if (content.trim().isEmpty) return DetectedFileType.unknown;
      final firstLine = content.split('\n').first.trim();
      if (firstLine.contains(':') || firstLine.contains(r'$')) {
        return DetectedFileType.hashFile;
      }
      if (firstLine.length >= 32 &&
          RegExp(r'^[a-fA-F0-9]+$').hasMatch(firstLine)) {
        return DetectedFileType.hashFile;
      }
    } catch (_) {
      return DetectedFileType.unknown;
    }
    return DetectedFileType.unknown;
  }

  // ══════════════════ 工具 ══════════════════

  static String _extensionOf(String path) {
    final name = path.split(RegExp(r'[/\\]')).last;
    final dot = name.lastIndexOf('.');
    if (dot <= 0 || dot == name.length - 1) return '';
    return name.substring(dot + 1).toLowerCase();
  }

  static Future<Uint8List> _readHeader(File file, int len) async {
    try {
      final raf = await file.open();
      try {
        final bytes = await raf.read(len);
        return Uint8List.fromList(bytes);
      } finally {
        await raf.close();
      }
    } catch (_) {
      return Uint8List(0);
    }
  }

  static Future<Uint8List?> _readTail(File file, int len) async {
    try {
      final raf = await file.open();
      try {
        final size = await raf.length();
        if (size < len) return null;
        await raf.setPosition(size - len);
        final bytes = await raf.read(len);
        return Uint8List.fromList(bytes);
      } finally {
        await raf.close();
      }
    } catch (_) {
      return null;
    }
  }
}
