/// 文件类型注册表与识别器的回归测试。
///
/// 这里锁的是「不依赖外部文件」的部分——所有样本都是用 dart:io 在临时目录
/// 现造的，再让识别器认。真正的样本会在端到端验证脚本里跑。
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/file_signatures.dart';
import 'package:hashcat_gui/models/file_type.dart';
import 'package:hashcat_gui/services/file_identifier.dart';

void main() {
  late Directory tempDir;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('file_id_');
  });

  tearDown(() async {
    if (await tempDir.exists()) await tempDir.delete(recursive: true);
  });

  String p(String name) => '${tempDir.path}${Platform.pathSeparator}$name';

  Future<void> writeBytes(String name, List<int> bytes) async {
    await File(p(name)).writeAsBytes(bytes);
  }

  Future<void> writeText(String name, String text) async {
    await File(p(name)).writeAsString(text);
  }

  group('注册表一致性', () {
    test('每个枚举值都有对应说明', () {
      for (final t in DetectedFileType.values) {
        final sig = FileSignatures.of(t);
        expect(sig.type, t, reason: '$t 必须能在 _index 里查到');
        expect(sig.label.isNotEmpty, true, reason: '$t 缺少中文名');
      }
    });

    test('有内置提取器的类型都标了 hashcat 模式', () {
      for (final sig in FileSignatures.all) {
        // hashFile 不是固定模式——每次识别都要让 hashcat 自己认。
        if (sig.type == DetectedFileType.hashFile) continue;
        if (sig.crackable) {
          expect(sig.modes.isNotEmpty, true,
              reason: '${sig.label} 标了 extractor=${sig.extractor} 但 modes 为空');
        }
      }
    });

    test('扩展名兜底用的类型必须真的有扩展名', () {
      for (final sig in FileSignatures.extensionOnly) {
        expect(sig.extensions.isNotEmpty, true,
            reason: '${sig.label} 没有扩展名却又走扩展名兜底');
      }
    });

    test('detectedFileType 扩展的所有 getter 都能调用', () {
      for (final t in DetectedFileType.values) {
        expect(t.label, isNotEmpty);
        expect(t.iconName, isNotEmpty);
        expect(t.category, isNotNull);
        expect(t.extractorTool, isNotEmpty);
        expect(t.guidance, isA<String>());
      }
    });
  });

  group('魔数识别', () {
    test('RAR3 (Rar!\x1A\x07\x00)', () async {
      await writeBytes('a.rar', [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
      expect(await FileIdentifier.identify(p('a.rar')), DetectedFileType.rar);
    });

    test('7-Zip (37 7A BC AF 27 1C)', () async {
      await writeBytes('a.7z', [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
      expect(await FileIdentifier.identify(p('a.7z')), DetectedFileType.sevenZip);
    });

    test('PDF (%PDF-)', () async {
      await writeBytes('a.pdf', '%PDF-1.7\n%...'.codeUnits);
      expect(await FileIdentifier.identify(p('a.pdf')), DetectedFileType.pdf);
    });

    test('Office 97-2003 (D0 CF 11 E0 A1 B1 1A E1)', () async {
      await writeBytes('a.doc',
      [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0, 0, 0]);
      expect(await FileIdentifier.identify(p('a.doc')), DetectedFileType.officeOld);
    });

    test('pcapng (0A 0D 0D 0A)', () async {
      await writeBytes('a.pcapng', [0x0A, 0x0D, 0x0D, 0x0A, 0x00, 0x00]);
      expect(await FileIdentifier.identify(p('a.pcapng')),
          DetectedFileType.pcapng);
    });

    test('LUKS (LUKSBA BE)', () async {
      await writeBytes('vol.luks', [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE]);
      expect(await FileIdentifier.identify(p('vol.luks')), DetectedFileType.luks);
    });

    test('APFS 魔数在偏移 32 (NXSB)', () async {
      final buf = Uint8List(40);
      for (var i = 0; i < 36; i++) {
        buf[i] = 0;
      }
      // 'NXSB'
      buf[32] = 0x4E;
      buf[33] = 0x58;
      buf[34] = 0x53;
      buf[35] = 0x42;
      buf[36] = 0x00;
      buf[37] = 0x10;
      buf[38] = 0x00;
      buf[39] = 0x00;
      await writeBytes('disk.img', buf);
      expect(await FileIdentifier.identify(p('disk.img')), DetectedFileType.apfs);
    });

    test('Windows 注册表配置单元 (regf)', () async {
      await writeBytes('SAM', [0x72, 0x65, 0x67, 0x66]);
      expect(await FileIdentifier.identify(p('SAM')), DetectedFileType.windowsHive);
    });

    test('Android 备份 (.ab)', () async {
      final sig = 'ANDROID BACKUP'.codeUnits;
      await writeBytes('bk.ab', sig);
      expect(await FileIdentifier.identify(p('bk.ab')), DetectedFileType.androidBackup);
    });

    test('KeePass KDBX (03 D9 A2 9A)', () async {
      await writeBytes('db.kdbx', [0x03, 0xD9, 0xA2, 0x9A, 1, 2]);
      expect(await FileIdentifier.identify(p('db.kdbx')), DetectedFileType.keepass);
    });

    test('Bitcoin wallet.dat (00 06 15 61)', () async {
      // 仅凭魔数不能识别 Bitcoin wallet——会落到 unknown（避免把别的 .dat 当 wallet.dat）。
      await writeBytes('foo.dat', [0x00, 0x06, 0x15, 0x61]);
      // 必须结合文件名 wallet.dat 才能识别（见 _byFileName）
      await writeBytes('wallet.dat', [0x00, 0x06, 0x15, 0x61, 0x00]);
      expect(await FileIdentifier.identify(p('wallet.dat')),
          DetectedFileType.bitcoinWallet);
    });
  });

  group('文件名特判', () {
    test('key4.db → mozillaKeyDb', () async {
      // 写一个伪 SQLite 头，让内容探针也能通过
      final hdr = 'SQLite format 3\u0000'.codeUnits;
      await writeBytes('key4.db', hdr);
      expect(await FileIdentifier.identify(p('key4.db')),
          DetectedFileType.mozillaKeyDb);
    });

    test('key3.db → mozillaKeyDb（无内容探针也能命中）', () async {
      await writeBytes('key3.db', [0, 0, 0, 0]);
      expect(await FileIdentifier.identify(p('key3.db')),
          DetectedFileType.mozillaKeyDb);
    });

    test('seco / .seco → exodus', () async {
      await writeBytes('seco', [0, 0, 0, 0]);
      expect(await FileIdentifier.identify(p('seco')), DetectedFileType.exodus);
    });

    test('UTC--*.json → ethereumWallet', () async {
      await writeText('UTC--2023-01-01T00-00-00Z--0xabc.json',
          '{"address":"0xabc","crypto":{"cipher":"aes-128-ctr"}}');
      final t = await FileIdentifier.identify(
          p('UTC--2023-01-01T00-00-00Z--0xabc.json'));
      expect(t, DetectedFileType.ethereumWallet);
    });

    test('.encfs6.xml → encfs', () async {
      await writeText('.encfs6.xml', '<config></config>');
      expect(await FileIdentifier.identify(p('.encfs6.xml')),
          DetectedFileType.encfs);
    });
  });

  group('文本探针', () {
    test('PEM 私钥 (-----BEGIN ... PRIVATE KEY-----)', () async {
      await writeText('id_rsa', '-----BEGIN RSA PRIVATE KEY-----\nABCD\n-----END RSA PRIVATE KEY-----');
      expect(await FileIdentifier.identify(p('id_rsa')), DetectedFileType.sshKey);
    });

    test('PuTTY 私钥', () async {
      await writeText('id.ppk', 'PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc');
      expect(await FileIdentifier.identify(p('id.ppk')), DetectedFileType.sshKey);
    });

    test('PGP ASCII armor', () async {
      await writeText('key.asc',
          '-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----');
      expect(await FileIdentifier.identify(p('key.asc')), DetectedFileType.pgpKey);
    });

    test('Ethereum keystore JSON（不带 UTC-- 前缀也能识别）', () async {
      final j = '{"address":"0xabc","crypto":{"cipher":"aes-128-ctr","kdf":"scrypt","mac":"..."}}';
      await writeText('random_name.json', j);
      expect(await FileIdentifier.identify(p('random_name.json')),
          DetectedFileType.ethereumWallet);
    });

    test('MetaMask vault JSON', () async {
      final j = '{"vault":{"data":"...","iv":"...","salt":"..."},"keyMetadata":{}}';
      await writeText('LDBLALALA.json', j);
      expect(await FileIdentifier.identify(p('LDBLALALA.json')),
          DetectedFileType.metamask);
    });

    test('VMware VMX (含 encryption.keySafe 与 .encoding)', () async {
      await writeText('win.vmx',
          'encryption.keySafe = "vmware-config-encoding"\n.displayName.encoding = "UTF-8"');
      expect(await FileIdentifier.identify(p('win.vmx')), DetectedFileType.vmwareVmx);
    });

    test('VirtualBox 加密磁盘配置', () async {
      await writeText('disk.vbox',
          '<?xml version="1.0"?><HardDisk><CRYPT/KeyStore></CRYPT></HardDisk>');
      expect(await FileIdentifier.identify(p('disk.vbox')),
          DetectedFileType.virtualboxVdi);
    });
  });

  group('扩展名兜底', () {
    test('.hc → veracrypt', () async {
      // VeraCrypt 没有固定魔数，只看扩展名
      await writeBytes('vol.hc', List<int>.filled(512, 0xAA));
      expect(await FileIdentifier.identify(p('vol.hc')), DetectedFileType.veracrypt);
    });

    test('.tc → truecrypt', () async {
      await writeBytes('vol.tc', List<int>.filled(512, 0xAA));
      expect(await FileIdentifier.identify(p('vol.tc')), DetectedFileType.truecrypt);
    });

    test('.kgb → kremlinKgb', () async {
      await writeBytes('secret.kgb', List<int>.filled(64, 0));
      expect(await FileIdentifier.identify(p('secret.kgb')),
          DetectedFileType.kremlinKgb);
    });

    test('.pcl → shiroPcl', () async {
      await writeBytes('rem.pcl', List<int>.filled(64, 0));
      expect(await FileIdentifier.identify(p('rem.pcl')),
          DetectedFileType.shiroPcl);
    });
  });

  group('哈希文本兜底', () {
    test('NTLM 格式（user:NTHASH）', () async {
      await writeText('h.txt', 'admin:8846f7eaee8fb117ad06bdd830b7586c');
      expect(await FileIdentifier.identify(p('h.txt')), DetectedFileType.hashFile);
    });

    test('bcrypt', () async {
      await writeText('h.txt',
          r'$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe');
      expect(await FileIdentifier.identify(p('h.txt')), DetectedFileType.hashFile);
    });

    test('32 hex 字符', () async {
      await writeText('h.txt', '5f4dcc3b5aa765d61d8327deb882cf99');
      expect(await FileIdentifier.identify(p('h.txt')), DetectedFileType.hashFile);
    });

    test('不含冒号也不含 \$ 的纯文本不该被当哈希', () async {
      await writeText('h.txt', '这是普通的笔记内容，没有冒号也没有美元符号。');
      expect(await FileIdentifier.identify(p('h.txt')), DetectedFileType.unknown);
    });
  });

  group('无法识别', () {
    test('不存在的文件', () async {
      expect(await FileIdentifier.identify(p('not_exist.bin')),
          DetectedFileType.unknown);
    });

    test('二进制乱码 → unknown', () async {
      await writeBytes('junk.bin', [0xFF, 0xFE, 0xCA, 0xFE, 0xBA, 0xBE, 0x00]);
      expect(await FileIdentifier.identify(p('junk.bin')), DetectedFileType.unknown);
    });
  });

  group('ZIP 家族细分', () {
    test('空文件但魔数是 PK 头 → ZIP', () async {
      await writeBytes('a.zip', [0x50, 0x4B, 0x03, 0x04]);
      // 没真正压缩内容时，会退到 zip
      expect(await FileIdentifier.identify(p('a.zip')), DetectedFileType.zip);
    });
  });
}