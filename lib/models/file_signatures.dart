import 'file_type.dart';

/// 识别出来的文件属于哪一大类。界面分组与文档表格用它来归类，
/// 比逐个枚举判断清爽得多。
enum FileCategory {
  archive('压缩包'),
  document('文档'),
  wifi('无线网络'),
  credential('密钥 / 凭据'),
  volume('磁盘与卷加密'),
  appData('应用 / 浏览器数据'),
  wallet('加密货币钱包'),
  windows('Windows 系统'),
  mobile('移动端'),
  java('Java / 应用服务器'),
  special('其它');

  const FileCategory(this.label);
  final String label;
}

/// 一条文件头特征。
///
/// 支持两种位置：
/// * [at] —— 从文件开头偏移 [offset] 处匹配 [bytes]
/// * [atEnd] —— 从文件末尾往前 [offset] 字节处匹配（DMG 的 `koly` 在尾部）
class MagicRule {
  final int offset;
  final List<int> bytes;
  final bool fromEnd;

  const MagicRule.at(this.offset, this.bytes) : fromEnd = false;
  const MagicRule.atEnd(this.offset, this.bytes) : fromEnd = true;
}

/// 一种文件类型的完整说明。
///
/// 这张表是整个识别层的唯一事实来源：识别、界面展示、提取路由、
/// 以及「提取不了时该怎么自己动手」都从这里取。
class FileSignature {
  final DetectedFileType type;

  /// 展示名称
  final String label;

  final FileCategory category;

  /// 图标名（由 task_card.dart 映射到具体的 Material 图标）
  final String iconName;

  /// 小写扩展名，不带点
  final List<String> extensions;

  /// 文件头特征；空表示只能靠扩展名/结构判断
  final List<MagicRule> magics;

  /// 是否属于 ZIP 容器家族（Office 新版 / ODF / iWork 都由 ZIP 承载，
  /// 需要进一步看压缩包内的目录结构才能区分）
  final bool zipFamily;

  /// 是否「只认内容、不认扩展名」。
  ///
  /// 这类格式的扩展名太常见（.json/.db）或者压根没有扩展名，
  /// 一旦参与扩展名兜底就会把别的东西误判成它，所以只能靠内容探针识别。
  final bool byContent;

  /// 提取器路由标识：
  /// * `''`                        —— 没有内置提取器（见 [guidance]）
  /// * `john:<name>`               —— runtime/tools 下的 john 脚本
  /// * `hc:<script前缀>`           —— runtime/hashcat/tools 下的官方转换器
  /// * `builtin:<name>`            —— 软件内置的解析器
  final String extractor;

  /// 界面上展示的「提取工具」名称
  final String extractorLabel;

  /// 该类型对应的 hashcat 模式（可能有多个候选，按推荐顺序）
  final List<int> modes;

  /// 没有内置提取器时的中文操作指引。为空表示本软件能直接处理。
  final String guidance;

  const FileSignature({
    required this.type,
    required this.label,
    required this.category,
    required this.iconName,
    this.extensions = const [],
    this.magics = const [],
    this.zipFamily = false,
    this.byContent = false,
    this.extractor = '',
    this.extractorLabel = '—',
    this.modes = const [],
    this.guidance = '',
  });

  /// 本软件能否直接「提取哈希 → 交给 hashcat」。
  bool get crackable => extractor.isNotEmpty;

  /// 提取器说明（给用户看的完整描述，含模式号）
  String get modeHint {
    if (modes.isEmpty) return '';
    if (modes.length == 1) return 'hashcat -m ${modes.first}';
    return 'hashcat -m ${modes.join(' / -m ')}';
  }
}

/// 全部已识别的文件类型。
///
/// 顺序即识别优先级：先判断更具体的特征，避免被宽泛的特征抢先命中。
/// ZIP 家族（[FileSignature.zipFamily]）统一交给结构探针判定，因此它们放在
/// 列表末尾，不会在文件头匹配阶段抢先命中。
class FileSignatures {
  const FileSignatures._();

  static const List<FileSignature> all = [
    // ══════════════════ 压缩包 ══════════════════
    FileSignature(
      type: DetectedFileType.rar,
      label: 'RAR 压缩包',
      category: FileCategory.archive,
      iconName: 'archive_lock',
      extensions: ['rar'],
      magics: [MagicRule.at(0, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])],
      modes: [12500, 23700, 23800, 13000],
      guidance: 'RAR 需要在打包时未加密文件头（WinRAR 的「加密文件名」未勾选）才能提取。'
          '本软件暂未内置 rar2john，可用 john the ripper 的 rar2john 生成哈希后，'
          '把哈希文本直接拖进来破解。RAR3-hp 用 -m 12500，RAR5 用 -m 13000。',
    ),
    FileSignature(
      type: DetectedFileType.sevenZip,
      label: '7-Zip 压缩包',
      category: FileCategory.archive,
      iconName: 'archive_lock',
      extensions: ['7z'],
      magics: [MagicRule.at(0, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])],
      modes: [11600],
      guidance: '7-Zip（-m 11600）的哈希需要用 7z2john 生成，而它依赖 Perl 运行时，'
          '本软件未内置。可以先用 7z2john.pl 生成 \$7z\$ 开头的哈希，'
          '再把哈希文本拖进来破解。',
    ),
    FileSignature(
      type: DetectedFileType.aesCrypt,
      label: 'AES Crypt 加密文件',
      category: FileCategory.archive,
      iconName: 'archive_lock',
      extensions: ['aes'],
      magics: [MagicRule.at(0, [0x41, 0x45, 0x53])],
      modes: [22400],
      guidance: 'AES Crypt（-m 22400）需要 aescrypt2hashcat.pl 提取，依赖 Perl。'
          '可在装有 Perl 的机器上生成哈希后再拖入本软件破解。',
    ),

    // ══════════════════ 文档 ══════════════════
    FileSignature(
      type: DetectedFileType.pdf,
      label: 'PDF 文档',
      category: FileCategory.document,
      iconName: 'pdf',
      extensions: ['pdf'],
      magics: [MagicRule.at(0, [0x25, 0x50, 0x44, 0x46])],
      extractor: 'john:pdf2john',
      extractorLabel: 'pdf2john',
      modes: [10400, 10500, 10600, 10700],
    ),
    FileSignature(
      type: DetectedFileType.officeOld,
      label: 'Office 文档 (97-2003)',
      category: FileCategory.document,
      iconName: 'document_locked',
      extensions: ['doc', 'xls', 'ppt'],
      magics: [
        MagicRule.at(0, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
      ],
      extractor: 'john:office2john',
      extractorLabel: 'office2john',
      modes: [9700, 9800],
    ),

    // ══════════════════ WiFi ══════════════════
    FileSignature(
      type: DetectedFileType.wifiHccapx,
      label: 'WiFi 握手包 (hccapx)',
      category: FileCategory.wifi,
      iconName: 'wifi',
      extensions: ['hccapx'],
      magics: [MagicRule.at(0, [0x48, 0x43, 0x50, 0x58])],
      modes: [2500],
      guidance: '.hccapx 是 hashcat 的二进制握手格式，不需要提取——'
          '但当前流程是按「文本哈希」传给 hashcat 的，二进制文件会被当成无效哈希。'
          '建议改用 .cap / .pcap / .pcapng 原始抓包，本软件会自动转成 -m 22000。',
    ),
    FileSignature(
      type: DetectedFileType.wifiPcap,
      label: 'WiFi 握手包 (pcap)',
      category: FileCategory.wifi,
      iconName: 'wifi',
      extensions: ['cap', 'pcap'],
      magics: [
        MagicRule.at(0, [0xD4, 0xC3, 0xB2, 0xA1]),
        MagicRule.at(0, [0xA1, 0xB2, 0xC3, 0xD4]),
        MagicRule.at(0, [0x4D, 0x3C, 0xB2, 0xA1]),
      ],
      extractor: 'builtin:wifi',
      extractorLabel: 'hcxpcapngtool',
      modes: [22000],
    ),
    FileSignature(
      type: DetectedFileType.pcapng,
      label: 'WiFi 握手包 (pcapng)',
      category: FileCategory.wifi,
      iconName: 'wifi',
      extensions: ['pcapng'],
      magics: [MagicRule.at(0, [0x0A, 0x0D, 0x0D, 0x0A])],
      extractor: 'builtin:wifi',
      extractorLabel: 'hcxpcapngtool',
      modes: [22000],
    ),

    // ══════════════════ 密钥 / 凭据 ══════════════════
    FileSignature(
      type: DetectedFileType.keepass,
      label: 'KeePass 数据库 (kdbx)',
      category: FileCategory.credential,
      iconName: 'shield_key',
      extensions: ['kdbx', 'kdb'],
      magics: [MagicRule.at(0, [0x03, 0xD9, 0xA2, 0x9A])],
      modes: [13400, 34300],
      guidance: 'KeePass KDBX v2/v3 用 -m 13400、v4 用 -m 34300。'
          '哈希需要用 keepass2john 提取，本软件未内置（该工具为 C 程序）。'
          '若数据库是「密钥文件 + 主密码」双因子，还需要一并提供密钥文件。',
    ),
    FileSignature(
      type: DetectedFileType.sshKey,
      label: 'SSH 私钥',
      category: FileCategory.credential,
      iconName: 'shield_key',
      extensions: ['pem', 'key', 'ppk', 'ppk2'],
      byContent: true,
      modes: [22911, 22921, 22931, 22941, 22951],
      guidance: 'SSH 私钥（-m 22911 等）需要用 ssh2john 转成 \$sshng\$ 哈希。'
          '本软件未内置该脚本，可用 john 生成后再把哈希文本拖进来。'
          '注意：只有「私钥本身被口令加密」才可破解，未加密的私钥没有可破的口令。',
    ),
    FileSignature(
      type: DetectedFileType.pgpKey,
      label: 'PGP / GPG 私钥',
      category: FileCategory.credential,
      iconName: 'shield_key',
      extensions: ['asc', 'gpg', 'pgp'],
      byContent: true,
      modes: [17010, 17020, 17030],
      guidance: 'GPG 私钥（-m 17010/17020/17030）需要 gpg2john 提取，本软件未内置。'
          'ASCII armor（-----BEGIN PGP PRIVATE KEY BLOCK-----）请先用 gpg 导出为'
          'john 能识别的格式，或直接用 john 生成哈希后拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.onePassword,
      label: '1Password 保险库',
      category: FileCategory.credential,
      iconName: 'shield_key',
      extensions: ['agilekeychain', 'opvault', '1pif'],
      modes: [6600, 8200, 31800],
      guidance: '1Password 保险库（-m 6600 agilekeychain / -m 8200 cloudkeychain）'
          '需要用 1password2john 提取。本软件未内置，可先自行生成哈希再拖入。',
    ),
    FileSignature(
      type: DetectedFileType.appleKeychain,
      label: 'Apple 钥匙串',
      category: FileCategory.credential,
      iconName: 'shield_key',
      extensions: ['keychain', 'keychain-db'],
      modes: [23100],
      guidance: 'macOS 钥匙串（-m 23100）需要 keychain2john 提取，本软件未内置。'
          '可在 macOS 上生成哈希后拖入本软件破解。',
    ),
    FileSignature(
      type: DetectedFileType.lastpass,
      label: 'LastPass 保险库',
      category: FileCategory.credential,
      iconName: 'shield_key',
      extensions: ['lpvault'],
      modes: [6800],
      guidance: 'LastPass（-m 6800）的提取需要同时提供账号邮箱，'
          '不同账号的哈希参数不同，因此无法全自动完成。'
          '可以运行 lastpass2hashcat.py <文件> <邮箱> 生成哈希后拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.bitwarden,
      label: 'Bitwarden 保险库',
      category: FileCategory.credential,
      iconName: 'shield_key',
      modes: [23400],
      guidance: 'Bitwarden（-m 23400）的凭据存放在浏览器扩展的本地存储里，'
          '需要先按工具说明导出 data.json 再用 bitwarden2hashcat.py 提取。',
    ),

    // ══════════════════ 磁盘与卷加密 ══════════════════
    FileSignature(
      type: DetectedFileType.bitlocker,
      label: 'BitLocker 加密卷',
      category: FileCategory.volume,
      iconName: 'hdd',
      magics: [
        MagicRule.at(3, [0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D]),
        MagicRule.at(0, [0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D]),
      ],
      extractor: 'hc:bitlocker2hashcat',
      extractorLabel: 'bitlocker2hashcat (hashcat)',
      modes: [22100],
    ),
    FileSignature(
      type: DetectedFileType.luks,
      label: 'LUKS 加密卷',
      category: FileCategory.volume,
      iconName: 'hdd',
      magics: [MagicRule.at(0, [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE])],
      extractor: 'hc:luks2hashcat',
      extractorLabel: 'luks2hashcat (hashcat)',
      modes: [29511, 29521, 29531, 29541, 34100],
    ),
    FileSignature(
      type: DetectedFileType.truecrypt,
      label: 'TrueCrypt 加密卷',
      category: FileCategory.volume,
      iconName: 'hdd',
      extensions: ['tc'],
      extractor: 'hc:truecrypt2hashcat',
      extractorLabel: 'truecrypt2hashcat (hashcat)',
      // 注意：不要用 6211/6212 这些「legacy」模式——hashcat 7 里它们已经
      // 无法加载 `$truecrypt$…` 形式的哈希（实测报 No hashes loaded）。
      // 现行模式是 293xx：RIPEMD160 / SHA512 / Whirlpool。
      modes: [29311, 29321, 29331],
    ),
    FileSignature(
      type: DetectedFileType.veracrypt,
      label: 'VeraCrypt 加密卷',
      category: FileCategory.volume,
      iconName: 'hdd',
      extensions: ['hc'],
      extractor: 'hc:veracrypt2hashcat',
      extractorLabel: 'veracrypt2hashcat (hashcat)',
      // 同上：用 294xx 而不是已失效的 13711 系列。
      modes: [29411, 29421, 29431, 29451, 29471],
    ),
    FileSignature(
      type: DetectedFileType.apfs,
      label: 'Apple APFS / FileVault',
      category: FileCategory.volume,
      iconName: 'hdd',
      magics: [MagicRule.at(32, [0x4E, 0x58, 0x53, 0x42])],
      modes: [18300, 16700],
      guidance: 'APFS（-m 18300）/ FileVault 2（-m 16700）需要 apfs2hashcat.py，'
          '而它依赖 Python 的 cryptography 库，本软件的内置 Python 未安装该库。'
          '可以在装了 cryptography 的机器上生成哈希后再拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.dmg,
      label: 'Apple DMG 磁盘映像',
      category: FileCategory.volume,
      iconName: 'disc',
      extensions: ['dmg'],
      magics: [MagicRule.atEnd(0, [0x6B, 0x6F, 0x6C, 0x79])],
      guidance: '加密 DMG 需要用 dmg2john 提取后才可破解，本软件未内置。'
          '常见的 DMG 是「有密码但未加密」，那种情况本身就没有可破的口令。',
    ),
    FileSignature(
      type: DetectedFileType.virtualboxVdi,
      label: 'VirtualBox 加密磁盘',
      category: FileCategory.volume,
      iconName: 'hdd',
      extensions: ['vbox'],
      magics: [
        MagicRule.at(0,
            [0x3C, 0x3C, 0x3C, 0x20, 0x4F, 0x72, 0x61, 0x63, 0x6C, 0x65]),
      ],
      extractor: 'hc:virtualbox2hashcat',
      extractorLabel: 'virtualbox2hashcat (hashcat)',
      modes: [27500, 27600],
    ),
    FileSignature(
      type: DetectedFileType.vmwareVmx,
      label: 'VMware VMX 加密虚拟机',
      category: FileCategory.volume,
      iconName: 'hdd',
      extensions: ['vmx'],
      extractor: 'hc:vmwarevmx2hashcat',
      extractorLabel: 'vmwarevmx2hashcat (hashcat)',
      modes: [27400],
    ),
    FileSignature(
      type: DetectedFileType.veeamVbk,
      label: 'Veeam 备份 (VBK)',
      category: FileCategory.volume,
      iconName: 'hdd',
      extensions: ['vbk'],
      extractor: 'hc:veeamvbk2hashcat',
      extractorLabel: 'veeamvbk2hashcat (hashcat)',
      modes: [31200],
    ),
    FileSignature(
      type: DetectedFileType.encfs,
      label: 'EncFS 加密目录',
      category: FileCategory.volume,
      iconName: 'hdd',
      extensions: ['encfs6'],
      byContent: true,
      modes: [29941],
      guidance: 'EncFS 需要 encfs2john 提取（依赖该格式的配置文件 .encfs6.xml），'
          '本软件未内置。可先自行生成哈希再拖入破解。',
    ),

    // ══════════════════ 应用 / 浏览器数据 ══════════════════
    FileSignature(
      type: DetectedFileType.mozillaKeyDb,
      label: 'Firefox 密码库 (key3/key4.db)',
      category: FileCategory.appData,
      iconName: 'browser',
      extensions: ['db'],
      byContent: true,
      modes: [26000, 26100],
      guidance: 'Firefox 的 key3.db（-m 26000）/ key4.db（-m 26100）需要 '
          'mozilla2hashcat.py，它依赖 Python 的 pycryptodome 与 pyasn1，'
          '内置 Python 未安装。可在装了依赖的环境生成哈希后拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.windowsCacheData,
      label: 'Windows 账户缓存 (CacheData)',
      category: FileCategory.appData,
      iconName: 'windows',
      extractor: 'hc:cachedata2hashcat',
      extractorLabel: 'cachedata2hashcat (hashcat)',
      modes: [31500],
    ),
    FileSignature(
      type: DetectedFileType.metamask,
      label: 'MetaMask 钱包保险库',
      category: FileCategory.appData,
      iconName: 'wallet',
      extensions: ['json'],
      byContent: true,
      extractor: 'hc:metamask2hashcat',
      extractorLabel: 'metamask2hashcat (hashcat)',
      modes: [26600, 26610],
    ),
    FileSignature(
      type: DetectedFileType.exodus,
      label: 'Exodus 钱包种子文件',
      category: FileCategory.appData,
      iconName: 'wallet',
      extensions: ['seco'],
      extractor: 'hc:exodus2hashcat',
      extractorLabel: 'exodus2hashcat (hashcat)',
      modes: [28200],
    ),

    // ══════════════════ 加密货币钱包 ══════════════════
    FileSignature(
      type: DetectedFileType.bitcoinWallet,
      label: 'Bitcoin Core 钱包 (wallet.dat)',
      category: FileCategory.wallet,
      iconName: 'wallet',
      extensions: ['dat'],
      magics: [MagicRule.at(0, [0x00, 0x06, 0x15, 0x61])],
      modes: [11300],
      guidance: 'Bitcoin Core 的 wallet.dat（-m 11300）需要 bitcoin2john 提取，'
          '依赖 Berkeley DB，本软件未内置。可先自行生成哈希再拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.ethereumWallet,
      label: 'Ethereum 钱包 (keystore)',
      category: FileCategory.wallet,
      iconName: 'wallet',
      extensions: ['json'],
      byContent: true,
      modes: [15600, 15700],
      guidance: 'Ethereum keystore（-m 15600 PBKDF2 / -m 15700 scrypt）本身是 JSON，'
          '内容形如 \$ethereum\$p*… 或 \$ethereum\$s*…。'
          '本软件暂未内置转换脚本，可先用 ethereum2john 生成哈希再拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.moneroWallet,
      label: 'Monero 钱包 (keys)',
      category: FileCategory.wallet,
      iconName: 'wallet',
      extensions: ['keys'],
      modes: [16600],
      guidance: 'Monero 钱包（-m 16600）需要 monero2john 提取，本软件未内置。',
    ),
    FileSignature(
      type: DetectedFileType.electrumWallet,
      label: 'Electrum 钱包',
      category: FileCategory.wallet,
      iconName: 'wallet',
      modes: [16600, 21700, 21800],
      guidance: 'Electrum 钱包（-m 16600/21700/21800）需要 electrum2john 提取，'
          '本软件未内置。可先自行生成 \$electrum\$ 哈希再拖入破解。',
    ),

    // ══════════════════ Windows 系统 ══════════════════
    FileSignature(
      type: DetectedFileType.windowsHive,
      label: 'Windows 注册表配置单元',
      category: FileCategory.windows,
      iconName: 'windows',
      magics: [MagicRule.at(0, [0x72, 0x65, 0x67, 0x66])],
      guidance: 'SAM / SYSTEM / SECURITY 等注册表配置单元不能直接破解，'
          '需要先用 secretsdump.py、pypykatz、mimikatz 等工具从 SAM+SYSTEM 中'
          '导出 NTLM 哈希，再把哈希文本拖进来（-m 1000）。',
    ),
    FileSignature(
      type: DetectedFileType.ntdsDit,
      label: 'Windows 域控数据库 (NTDS.dit)',
      category: FileCategory.windows,
      iconName: 'windows',
      magics: [MagicRule.at(4, [0xEF, 0xCD, 0xAB, 0x89])],
      guidance: 'NTDS.dit 需要配合 SYSTEM 配置单元，用 secretsdump.py 导出域内'
          '全部 NTLM 哈希后再破解（-m 1000）。本软件不直接处理该文件。',
    ),

    // ══════════════════ 移动端 ══════════════════
    FileSignature(
      type: DetectedFileType.androidBackup,
      label: 'Android 备份 (.ab)',
      category: FileCategory.mobile,
      iconName: 'phone',
      extensions: ['ab', 'backup'],
      magics: [
        MagicRule.at(0, [
          0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x20, // "ANDROID "
          0x42, 0x41, 0x43, 0x4B, 0x55, 0x50, // "BACKUP"
        ]),
      ],
      modes: [18900],
      guidance: 'Android 备份（-m 18900）需要 androidbackup2john 提取。'
          '只有「设了备份密码」的 .ab 才有可破的口令，无密码备份无法破解。',
    ),

    // ══════════════════ Java / 应用服务器 ══════════════════
    FileSignature(
      type: DetectedFileType.shiroPcl,
      label: 'Apache Shiro 序列化文件 (.pcl)',
      category: FileCategory.java,
      iconName: 'java',
      extensions: ['pcl'],
      extractor: 'hc:shiro1-to-hashcat',
      extractorLabel: 'shiro1-to-hashcat (hashcat)',
      modes: [12150],
    ),
    FileSignature(
      type: DetectedFileType.kremlinKgb,
      label: 'Kremlin Encrypt 文件 (.kgb)',
      category: FileCategory.java,
      iconName: 'java',
      extensions: ['kgb'],
      extractor: 'hc:kremlin2hashcat',
      extractorLabel: 'kremlin2hashcat (hashcat)',
      modes: [32700],
    ),

    // ══════════════════ ZIP 家族（由结构探针细分） ══════════════════
    FileSignature(
      type: DetectedFileType.officeNew,
      label: 'Office 文档 (2007+)',
      category: FileCategory.document,
      iconName: 'document_locked',
      extensions: ['docx', 'xlsx', 'pptx'],
      zipFamily: true,
      extractor: 'john:office2john',
      extractorLabel: 'office2john',
      modes: [9400, 9500, 9600],
    ),
    FileSignature(
      type: DetectedFileType.openDocument,
      label: 'LibreOffice / OpenDocument',
      category: FileCategory.document,
      iconName: 'document_locked',
      extensions: ['odt', 'ods', 'odp', 'odg', 'odf'],
      zipFamily: true,
      modes: [18400, 18600],
      guidance: 'ODF 加密文档（-m 18400）需要 libreoffice2john 提取，'
          '本软件暂未内置。可先用 john 生成哈希后再拖入破解。',
    ),
    FileSignature(
      type: DetectedFileType.iwork,
      label: 'Apple iWork 文档',
      category: FileCategory.document,
      iconName: 'document_locked',
      extensions: ['pages', 'numbers', 'key'],
      zipFamily: true,
      modes: [23300],
      guidance: 'iWork（-m 23300）需要 iwork2john 提取，本软件暂未内置。',
    ),
    FileSignature(
      type: DetectedFileType.zip,
      label: 'ZIP 压缩包',
      category: FileCategory.archive,
      iconName: 'archive_lock',
      extensions: ['zip'],
      magics: [
        MagicRule.at(0, [0x50, 0x4B, 0x03, 0x04]),
        MagicRule.at(0, [0x50, 0x4B, 0x05, 0x06]),
        MagicRule.at(0, [0x50, 0x4B, 0x07, 0x08]),
      ],
      zipFamily: true,
      extractor: 'john:zip2john',
      extractorLabel: 'zip2john',
      modes: [17200, 17210, 17220, 17225, 17230, 13600],
    ),

    // ══════════════════ 特殊（不参与文件头匹配）══════════════════
    // 这三个在识别链的最外层就被分流走了（hashFile 是文本兜底；mifareDump /
    // nonceLog 在 file_identifier 的第 1 步就通过 MIFARE 内容特判定向了），
    // 但保持注册表覆盖它们，以便 DetectedFileTypeInfo 的扩展能给出统一的
    // label/icon/extractor/modes 视图。
    FileSignature(
      type: DetectedFileType.hashFile,
      label: '原始哈希文本',
      category: FileCategory.special,
      iconName: 'fingerprint',
      extractor: 'builtin:identify',
      extractorLabel: 'hashcat --identify',
      guidance: '本软件会用 hashcat 自带的 --identify 自动识别它属于哪一种哈希，'
          '不需要预先指定模式。多模式兼容时按常见程度依次尝试。',
    ),
    FileSignature(
      type: DetectedFileType.mifareDump,
      label: 'MIFARE Classic 转储',
      category: FileCategory.special,
      iconName: 'nfc',
      guidance: 'MIFARE 卡片转储不能直接交给 hashcat——卡上没有密文也没有 nonce，'
          '没有任何东西可以验证猜测的密钥。请使用「MIFARE 卡片分析器」做诊断与密钥恢复。',
    ),
    FileSignature(
      type: DetectedFileType.nonceLog,
      label: 'MIFARE mfkey32 nonce 日志',
      category: FileCategory.special,
      iconName: 'vpn_key',
      guidance: 'nonce 日志是 mfkey32 攻击的输入。用「MIFARE 卡片分析器 → 密钥恢复」'
          '导入后，本软件会用 Crypto1 状态恢复离线算出密钥。',
    ),
  ];

  /// 类型 → 说明。识别、界面、提取都从这里查。
  static final Map<DetectedFileType, FileSignature> _index = {
    for (final s in all) s.type: s,
  };

  static FileSignature of(DetectedFileType type) =>
      _index[type] ?? unknown;

  static const FileSignature unknown = FileSignature(
    type: DetectedFileType.unknown,
    label: '未知类型',
    category: FileCategory.special,
    iconName: 'help',
    guidance: '无法识别该文件的加密类型。若它本身就是一段哈希文本，'
        '可以直接把哈希内容粘贴进输入框破解。',
  );

  /// 特殊类型（不参与文件头匹配）
  static const List<DetectedFileType> specialTypes = [
    DetectedFileType.hashFile,
    DetectedFileType.mifareDump,
    DetectedFileType.nonceLog,
    DetectedFileType.unknown,
  ];

  /// 能通过魔数/结构精确识别的类型
  static Iterable<FileSignature> get magicMatchable =>
      all.where((s) => s.magics.isNotEmpty && !s.zipFamily);

  /// 仅靠扩展名识别的类型（魔数随机或缺失）
  static Iterable<FileSignature> get extensionOnly => all.where((s) =>
      s.magics.isEmpty && !s.zipFamily && !s.byContent &&
      s.extensions.isNotEmpty);

  /// 收集所有被识别的扩展名（供文件选择器过滤）
  static List<String> get allExtensions {
    final set = <String>{};
    for (final s in all) {
      set.addAll(s.extensions);
    }
    // 常见但上面没列全的别名与特殊扩展
    set.addAll([
      'txt', 'hash', 'hsh', 'nfc', 'shd', 'eml', 'bin', 'mfd', 'log',
      'dat', 'db', 'json', 'xml', 'pcap', 'cap', 'pcapng', 'hccapx',
    ]);
    return set.toList()..sort();
  }
}

/// `DetectedFileType` 的展示信息统一入口。
extension DetectedFileTypeInfo on DetectedFileType {
  FileSignature get signature => FileSignatures.of(this);

  /// 中文名称
  String get label => signature.label;

  /// 图标名（task_card.dart 负责映射到 Material 图标）
  String get iconName => signature.iconName;

  FileCategory get category => signature.category;

  /// 提取工具名称
  String get extractorTool => signature.extractorLabel;

  /// 该类型对应的 hashcat 模式
  List<int> get modes => signature.modes;

  /// 能否直接提取 + 破解
  bool get crackable => signature.crackable;

  /// 没有内置提取器时的中文指引
  String get guidance => signature.guidance;
}
