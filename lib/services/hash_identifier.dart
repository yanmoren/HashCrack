import 'dart:io';

/// 一个候选的 hashcat 模式。
class HashModeCandidate {
  final int mode;
  final String name;
  final String category;

  const HashModeCandidate({
    required this.mode,
    required this.name,
    this.category = '',
  });

  @override
  String toString() => '$mode ($name)';
}

/// 原始哈希的识别结果。
class HashIdentifyResult {
  final bool ok;

  /// 全部候选，已按「实际使用中出现的常见程度」重排（不是 hashcat 的输出顺序）
  final List<HashModeCandidate> candidates;

  /// hashcat 是否无法唯一确定（多个模式结构相符）
  final bool ambiguous;

  /// 失败原因 / 额外说明
  final String note;

  const HashIdentifyResult({
    this.ok = false,
    this.candidates = const [],
    this.ambiguous = false,
    this.note = '',
  });

  bool get isEmpty => candidates.isEmpty;

  /// 候选模式编号（按推荐顺序）
  List<int> get modes => candidates.map((c) => c.mode).toList();

  /// 首选模式；没有候选时返回 0
  int get primaryMode => candidates.isEmpty ? 0 : candidates.first.mode;

  String get summary {
    if (candidates.isEmpty) return '';
    if (candidates.length == 1) {
      return '${candidates.first.mode} (${candidates.first.name})';
    }
    return candidates.take(5).map((c) => '${c.mode}').join(' / ');
  }
}

/// 原始哈希类型识别。
///
/// 优先使用 hashcat 自带的 `--identify`——这是权威且覆盖最全的做法
/// （580 多个模式，我们不可能自己维护一套规则去比它的覆盖度）。
/// 只有拿不到 hashcat 时才退回内置的规则匹配。
///
/// 两个必须注意的点：
/// 1. hashcat 的 `--identify` 在**多个模式结构相符时不会替我们做选择**
///    （比如 32 位十六进制既可能是 MD5 也可能是 NTLM、MD4），它只把候选列出来。
///    所以真正的「选哪个」必须由我们决定，见 [reorderByCommonality]。
/// 2. 它必须在 hashcat 自己的目录下运行，否则会报 `./OpenCL/: No such file`。
class HashIdentifier {
  final String hashcatPath;

  HashIdentifier({required this.hashcatPath});

  /// 常见模式优先级表。
  ///
  /// 这是「当 hashcat 给出多个候选时挑谁先试」的依据。顺序按真实使用频率
  /// 排：32 位十六进制优先当 MD5 而不是 MD4（虽然 hashcat 把 MD4 列在前面），
  /// `$2*$` 优先当作标准 bcrypt 而不是 bcrypt(md5(...))。
  static const List<int> _commonFirst = [
    0, // MD5
    100, // SHA1
    1400, // SHA2-256
    1700, // SHA2-512
    1000, // NTLM
    3000, // LM
    5500, // NetNTLMv1
    5600, // NetNTLMv2
    22000, // WPA-PBKDF2-PMKID+EAPOL
    500, // md5crypt
    1800, // sha512crypt
    7400, // sha256crypt
    3200, // bcrypt
    1600, // Apache $apr1$
    400, // phpass
    300, // MySQL4.1/MySQL5
    10, // md5($pass.$salt)
    20, // md5($salt.$pass)
    1300, // sha1($pass.$salt)
    1500, // sha1($salt.$pass)
    900, // MD4
    2600, // md5(md5($pass))
    70, // md5(utf16le($pass))
    6000, // RIPEMD-160
    10900, // PBKDF2-HMAC-SHA256
    13600, // WinZip AES
    17200, // PKZIP Compressed
    17210,
    17220,
    17225,
    17230,
    10400, // PDF 1.1-1.3
    10500, // PDF 1.4-1.6
    10600, // PDF 1.7 L3
    10700, // PDF 1.7 L8
    9400, // Office 2007
    9500, // Office 2010
    9600, // Office 2013
    9700, // Office <=2003
    9800,
    11600, // 7-Zip
    12500, // RAR3-hp
    13000, // RAR5
    13400, // KeePass
    11300, // Bitcoin wallet.dat
    15600, // Ethereum (PBKDF2)
    15700, // Ethereum (scrypt)
    16600, // Electrum / Monero
    22911, // SSH ($0$)
    22921,
    22931,
    22941,
    22951,
    22100, // BitLocker
    // TrueCrypt / VeraCrypt 用新的 293xx / 294xx 系列；
    // 旧的 6211 / 13711 在 hashcat 7 里已无法加载 $truecrypt$ 形式的哈希。
    29311, // TrueCrypt RIPEMD160
    29321, // TrueCrypt SHA512
    29331, // TrueCrypt Whirlpool
    29411, // VeraCrypt RIPEMD160
    29421, // VeraCrypt SHA512
    29431, // VeraCrypt Whirlpool
    29451, // VeraCrypt SHA256
    29471, // VeraCrypt Streebog-512
    23400, // Bitwarden
    26600, // MetaMask
    28200, // Exodus
    18900, // Android Backup
    12150, // Apache Shiro
    32700, // Kremlin
    31200, // Veeam VBK
    27500, // VirtualBox
    27400, // VMware VMX
    29511, // LUKS v1 SHA-1 + AES
    29521,
    29531,
    29541,
    34100, // LUKS v2 argon2
    23100, // Apple Keychain
    6800, // LastPass
    26000, // Mozilla key3.db
    26100, // Mozilla key4.db
    16200, // Apple Secure Notes
    17010, // GPG
    17020,
    17030,
  ];

  /// 单次识别最多尝试多少个候选模式。
  ///
  /// 32 位十六进制能匹配出十几个模式，全试一遍在慢哈希上代价很大；
  /// 取前若干个「常见度最高的」已经能覆盖绝大多数真实场景。
  static const int maxCandidates = 6;

  /// 识别哈希文本。
  Future<HashIdentifyResult> identify(String hashText) async {
    final text = hashText.trim();
    if (text.isEmpty) {
      return const HashIdentifyResult(ok: false, note: '哈希内容为空');
    }

    final exe = hashcatPath;
    if (exe.isEmpty || !File(exe).existsSync()) {
      final fallback = fallbackCandidates(text);
      return HashIdentifyResult(
        ok: fallback.isNotEmpty,
        candidates: fallback,
        ambiguous: fallback.length > 1,
        note: fallback.isEmpty
            ? 'hashcat 不可用，且内置规则也认不出这段哈希'
            : 'hashcat 不可用，以下结果来自内置规则匹配',
      );
    }

    // 逐行尝试：用户给的可能是一整份哈希文件，取第一个能被识别的行即可；
    // 也可能是 `用户名:哈希` 形式，需要把前缀去掉再试一次。
    final lines = text
        .split(RegExp(r'\r\n|\r|\n'))
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty)
        .toList();

    final tried = <String>{};
    for (final line in lines) {
      final variants = <String>[line];
      // `user:hash`：只有当冒号前不像哈希内容时才尝试剥离
      final colon = line.indexOf(':');
      if (colon > 0) {
        final prefix = line.substring(0, colon);
        if (!prefix.contains(r'$')) variants.add(line.substring(colon + 1));
      }
      for (final v in variants) {
        if (!tried.add(v)) continue;
        final raw = await _runIdentify(exe, v);
        if (raw != null && raw.isNotEmpty) {
          final ordered = reorderByCommonality(raw);
          return HashIdentifyResult(
            ok: true,
            candidates: ordered,
            ambiguous: ordered.length > 1,
            note: ordered.length > 1
                ? '结构上符合多个模式，将按常见程度依次尝试'
                : '',
          );
        }
      }
    }

    return const HashIdentifyResult(
      ok: false,
      note: 'hashcat 未能识别这段哈希的结构',
    );
  }

  /// 调用 `hashcat --identify`，返回候选模式列表（未排序）。
  Future<List<HashModeCandidate>?> _runIdentify(
      String exe, String hash) async {
    final tmp = File(
      '${Directory.systemTemp.absolute.path}${Platform.pathSeparator}'
      'hc_identify_${DateTime.now().microsecondsSinceEpoch}.txt',
    );
    try {
      await tmp.writeAsString('$hash\n');
      final r = await Process.run(
        exe,
        ['--identify', tmp.path],
        // 必须用 hashcat 自己的目录作为工作目录，否则它找不到 ./OpenCL/
        workingDirectory: File(exe).parent.path,
        stdoutEncoding: null,
        stderrEncoding: null,
      ).timeout(const Duration(seconds: 120));

      final out = '${String.fromCharCodes(r.stdout as List<int>)}\n'
          '${String.fromCharCodes(r.stderr as List<int>)}';
      return parseIdentifyOutput(out);
    } catch (_) {
      return null;
    } finally {
      try {
        if (await tmp.exists()) await tmp.delete();
      } catch (_) {}
    }
  }

  /// 解析 `hashcat --identify` 的输出。
  ///
  /// 输出形如（注意 banner 与表格之间只有 \r，必须同时按 \r 和 \n 切分）：
  /// ```
  ///     900 | MD4                    | Raw Hash
  ///       0 | MD5                    | Raw Hash
  /// ```
  static List<HashModeCandidate> parseIdentifyOutput(String raw) {
    final result = <HashModeCandidate>[];
    final seen = <int>{};
    for (final line in raw.split(RegExp(r'\r\n|\r|\n'))) {
      final t = line.trim();
      if (t.isEmpty) continue;
      final m = RegExp(r'^(\d+)\s*\|\s*(.+?)\s*\|\s*(.*)$').firstMatch(t);
      if (m == null) continue;
      final mode = int.tryParse(m.group(1)!);
      if (mode == null || !seen.add(mode)) continue;
      result.add(HashModeCandidate(
        mode: mode,
        name: m.group(2)!.trim(),
        category: m.group(3)!.trim(),
      ));
    }
    return result;
  }

  /// 按常见程度重排候选，并截断到 [maxCandidates]。
  static List<HashModeCandidate> reorderByCommonality(
      List<HashModeCandidate> candidates) {
    if (candidates.length <= 1) return candidates;

    final byMode = {for (final c in candidates) c.mode: c};
    final ordered = <HashModeCandidate>[];
    final used = <int>{};

    // 先按优先级表挑
    for (final mode in _commonFirst) {
      final c = byMode[mode];
      if (c != null && used.add(mode)) ordered.add(c);
      if (ordered.length >= maxCandidates) return ordered;
    }
    // 剩下的保持 hashcat 给出的原始顺序兜底
    for (final c in candidates) {
      if (used.add(c.mode)) ordered.add(c);
      if (ordered.length >= maxCandidates) break;
    }
    return ordered;
  }

  // ══════════════════ 不依赖 hashcat 的内置规则 ══════════════════

  /// 由 LUKS 哈希前缀推断具体模式。
  ///
  /// 形式为 `$luks$<版本>$<哈希>$<加密算法>$<模式>$<密钥长度>$<迭代>$<数据>`：
  /// * 版本 2（LUKS2 / argon2）统一是 34100
  /// * 版本 1 按「哈希算法 × 加密算法」组合成不同的模式号：
  ///   sha1=29511 / sha256=29521 / sha512=29531 / ripemd160=29541，
  ///   同一哈希下 aes/serpent/twofish 依次 +0/+1/+2。
  static int luksMode(String hash) {
    final p = hash.split(r'$');
    // p[0] 是空前缀，p[1]='luks'，p[2]=版本，p[3]=哈希，p[4]=算法
    if (p.length < 5) return 29511;
    if (p[2] == '2') return 34100;

    final h = p[3].toLowerCase();
    final cipher = p[4].toLowerCase();
    final base = switch (h) {
      'sha1' => 29511,
      'sha256' => 29521,
      'sha512' => 29531,
      'ripemd160' => 29541,
      _ => 29511,
    };
    if (cipher.contains('serpent')) return base + 1;
    if (cipher.contains('twofish')) return base + 2;
    return base; // aes 及其它
  }

  /// 纯规则匹配，用于没有 hashcat 的场景（以及单元测试）。
  ///
  /// 覆盖的是「一眼能认出来」的格式；判断不了就返回空列表，
  /// 交给用户在界面上自己指定模式，而不是猜一个错误的结果。
  static List<HashModeCandidate> fallbackCandidates(String hash) {
    final h = hash.trim();
    if (h.isEmpty) return const [];

    HashModeCandidate c(int mode, String name, [String cat = '']) =>
        HashModeCandidate(mode: mode, name: name, category: cat);

    // ── 带前缀的确定性格式 ────────────────────────────────
    if (h.startsWith(r'$1$')) return [c(500, 'md5crypt, MD5 (Unix)')];
    if (h.startsWith(r'$apr1$')) return [c(1600, 'Apache \$apr1\$ MD5')];
    if (h.startsWith(r'$2a$') ||
        h.startsWith(r'$2b$') ||
        h.startsWith(r'$2x$') ||
        h.startsWith(r'$2y$')) {
      return [c(3200, 'bcrypt \$2*\$')];
    }
    if (h.startsWith(r'$5$')) return [c(7400, 'sha256crypt')];
    if (h.startsWith(r'$6$')) return [c(1800, 'sha512crypt')];
    if (h.startsWith(r'$P$') || h.startsWith(r'$H$')) {
      return [c(400, 'phpass (WordPress/Joomla)')];
    }
    if (h.startsWith('WPA*')) {
      return [c(22000, 'WPA-PBKDF2-PMKID+EAPOL', 'Network Protocol')];
    }
    if (h.startsWith(r'$zip2$')) return [c(13600, 'WinZip AES')];
    if (h.startsWith(r'$pkzip2$') || h.startsWith(r'$pkzip$')) {
      return [
        c(17200, 'PKZIP (Compressed)'),
        c(17210, 'PKZIP (Uncompressed)'),
        c(17220, 'PKZIP (Compressed Multi-File)'),
        c(17225, 'PKZIP (Mixed Multi-File)'),
      ];
    }
    if (h.startsWith(r'$pdf$')) {
      if (h.contains(r'$pdf$1*')) return [c(10400, 'PDF 1.1-1.3')];
      if (h.contains(r'$pdf$2*')) return [c(10600, 'PDF 1.7 Level 3')];
      if (h.contains(r'$pdf$4*')) return [c(10500, 'PDF 1.4-1.6')];
      if (h.contains(r'$pdf$5*')) return [c(10700, 'PDF 1.7 Level 8')];
      return [c(10400, 'PDF')];
    }
    if (h.contains(r'$office$')) {
      if (h.contains('2007')) return [c(9400, 'MS Office 2007')];
      if (h.contains('2010')) return [c(9500, 'MS Office 2010')];
      if (h.contains('2013')) return [c(9600, 'MS Office 2013')];
      return [c(9600, 'MS Office')];
    }
    if (h.contains(r'$oldoffice$')) {
      return [c(9700, 'MS Office <=2003 (MD5+RC4)'),
              c(9800, 'MS Office <=2003 (SHA1+RC4)')];
    }
    if (h.startsWith(r'$7z$')) return [c(11600, '7-Zip')];
    if (h.startsWith(r'$RAR3$')) return [c(12500, 'RAR3-hp')];
    if (h.startsWith(r'$rar5$')) return [c(13000, 'RAR5')];
    if (h.startsWith(r'$keepass$')) {
      // v2/v3 与 v4 是不同模式，靠 `*2*` / `*4*` 区分
      if (h.startsWith(r'$keepass$*4*')) {
        return [c(34300, 'KeePass (KDBX v4)')];
      }
      return [c(13400, 'KeePass (KDBX v2/v3)')];
    }
    if (h.startsWith(r'$bitcoin$')) return [c(11300, 'Bitcoin wallet.dat')];
    if (h.startsWith(r'$ethereum$s')) return [c(15700, 'Ethereum (scrypt)')];
    if (h.startsWith(r'$ethereum$p')) return [c(15600, 'Ethereum (PBKDF2)')];
    if (h.startsWith(r'$electrum$')) return [c(16600, 'Electrum Wallet')];
    if (h.startsWith(r'$sshng$')) {
      return [
        c(22911, r'OpenSSH Private Key ($0$)'),
        c(22921, r'OpenSSH Private Key ($6$)'),
        c(22931, r'OpenSSH Private Key ($1, $3$)'),
        c(22941, r'OpenSSH Private Key ($4$)'),
        c(22951, r'OpenSSH Private Key ($5$)'),
      ];
    }
    if (h.startsWith(r'$bitlocker$')) return [c(22100, 'BitLocker')];
    if (h.startsWith(r'$luks$')) return [c(luksMode(h), 'LUKS')];
    if (h.startsWith(r'$truecrypt$')) {
      // 不要用 6211 等 legacy 模式，hashcat 7 已无法加载该形式的哈希
      return [
        c(29311, 'TrueCrypt RIPEMD160 + XTS 512'),
        c(29321, 'TrueCrypt SHA512 + XTS 512'),
        c(29331, 'TrueCrypt Whirlpool + XTS 512'),
      ];
    }
    if (h.startsWith(r'$veracrypt$')) {
      return [
        c(29411, 'VeraCrypt RIPEMD160 + XTS 512'),
        c(29421, 'VeraCrypt SHA512 + XTS 512'),
        c(29431, 'VeraCrypt Whirlpool + XTS 512'),
        c(29451, 'VeraCrypt SHA256 + XTS 512'),
        c(29471, 'VeraCrypt Streebog-512 + XTS 512'),
      ];
    }
    if (h.startsWith(r'$bitwarden$')) return [c(23400, 'Bitwarden')];
    if (h.startsWith(r'$metamask$')) return [c(26600, 'MetaMask Wallet')];
    if (h.startsWith('EXODUS:')) return [c(28200, 'Exodus Desktop Wallet')];
    if (h.startsWith(r'$ab$')) return [c(18900, 'Android Backup')];
    if (h.startsWith(r'$shiro1$')) return [c(12150, 'Apache Shiro 1 SHA-512')];
    if (h.startsWith(r'$kgb$')) return [c(32700, 'Kremlin Encrypt')];
    if (h.startsWith(r'$vbk$')) return [c(31200, 'Veeam VBK')];
    if (h.startsWith(r'$vbox$')) return [c(27500, 'VirtualBox')];
    if (h.startsWith(r'$vmx$')) return [c(27400, 'VMware VMX')];
    if (h.startsWith(r'$odf$')) return [c(18400, 'OpenDocument 1.2')];
    if (h.startsWith(r'$iwork$')) return [c(23300, 'Apple iWork')];

    // ── 纯十六进制：按长度推断 ────────────────────────────
    if (RegExp(r'^[a-fA-F0-9]+$').hasMatch(h)) {
      switch (h.length) {
        case 32:
          return [
            c(0, 'MD5', 'Raw Hash'),
            c(1000, 'NTLM', 'Operating System'),
            c(900, 'MD4', 'Raw Hash'),
            c(2600, r'md5(md5($pass))'),
            c(70, r'md5(utf16le($pass))'),
          ];
        case 40:
          return [
            c(100, 'SHA1', 'Raw Hash'),
            c(1300, r'sha1($pass.$salt)'),
            c(1500, r'sha1($salt.$pass)'),
          ];
        case 64:
          return [
            c(1400, 'SHA2-256', 'Raw Hash'),
            c(1740, r'sha256($salt.$pass)'),
            c(10900, 'PBKDF2-HMAC-SHA256'),
          ];
        case 128:
          return [c(1700, 'SHA2-512', 'Raw Hash')];
        case 16:
          return [c(5100, 'Half MD5')];
        default:
          return const [];
      }
    }

    // DES(Unix)：13 个可见字符
    if (h.length == 13 && RegExp(r'^[./0-9A-Za-z]{13}$').hasMatch(h)) {
      return [c(1500, 'DES(Unix)')];
    }

    return const [];
  }
}
