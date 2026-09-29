/// 软件能识别的文件类型。
///
/// 这里只放枚举本身；每种类型的名称、图标、提取器、对应的 hashcat 模式、
/// 以及「没有内置提取器时该怎么办」统一放在 `file_signatures.dart` 的注册表里，
/// 避免两个文件互相 import 形成环。
///
/// 划分依据是 **hashcat 能破解的载体**：要么是加密的容器/文档
/// （zip/rar/pdf/office…），要么是需要先提取出哈希的卷、密钥、钱包、
/// 浏览器与应用数据。凡是「本软件识别得出、hashcat 有对应模式」的都在这里。
enum DetectedFileType {
  // ── 压缩包 ─────────────────────────────────────────────
  zip,
  rar,
  sevenZip,
  aesCrypt,

  // ── 文档 ───────────────────────────────────────────────
  pdf,
  officeNew,
  officeOld,
  openDocument,
  iwork,

  // ── WiFi ──────────────────────────────────────────────
  wifiPcap,
  pcapng,
  wifiHccapx,

  // ── 密钥与凭据 ─────────────────────────────────────────
  sshKey,
  pgpKey,
  keepass,
  onePassword,
  appleKeychain,

  // ── 卷 / 磁盘加密 ──────────────────────────────────────
  bitlocker,
  luks,
  truecrypt,
  veracrypt,
  apfs,
  dmg,
  virtualboxVdi,
  vmwareVmx,
  veeamVbk,
  encfs,

  // ── 应用 / 浏览器数据 ──────────────────────────────────
  mozillaKeyDb,
  windowsCacheData,
  lastpass,
  bitwarden,
  metamask,
  exodus,

  // ── 加密货币钱包 ───────────────────────────────────────
  bitcoinWallet,
  ethereumWallet,
  moneroWallet,
  electrumWallet,

  // ── Windows 系统 ───────────────────────────────────────
  windowsHive,
  ntdsDit,

  // ── 移动端 ─────────────────────────────────────────────
  androidBackup,

  // ── Java / 应用服务器 ──────────────────────────────────
  shiroPcl,
  kremlinKgb,

  // ── 特殊 ───────────────────────────────────────────────
  /// 已经是哈希文本（任意 hashcat 支持的模式）
  hashFile,

  /// MIFARE Classic 转储（Flipper .nfc/.shd、Proxmark .eml、裸 .bin/.mfd）
  mifareDump,

  /// mfkey32 的 nonce 日志（Flipper `mfkey32.log` 等），用于离线恢复密钥
  nonceLog,

  unknown,
}
