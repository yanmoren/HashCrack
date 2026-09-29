/// 原始哈希类型识别的回归测试。
///
/// 这里只测「不依赖 hashcat 二进制」的纯规则匹配（fallbackCandidates），
/// 以及 parseIdentifyOutput 的格式解析。完整端到端测试需要把 hashcat
/// 一起跑，那放在专门的端到端脚本里。
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/services/hash_identifier.dart';

void main() {
  group('fallbackCandidates', () {
    test(r'$1$ md5crypt → 500', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$1$28772684$iEwNOgGugqO9.bIz5sk8k/');
      expect(c.length, 1);
      expect(c.first.mode, 500);
    });

    test(r'$apr1$ → 1600', () {
      final c =
          HashIdentifier.fallbackCandidates(r'$apr1$abc$xyz');
      expect(c.first.mode, 1600);
    });

    test(r'$2a$/$2b$/$2y$ → 3200', () {
      for (final v in [
        r'$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
        r'$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m',
        r'$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe',
      ]) {
        final c = HashIdentifier.fallbackCandidates(v);
        expect(c.first.mode, 3200, reason: '$v 应识别为 bcrypt');
      }
    });

    test(r'$5$ → 7400 (sha256crypt)', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$5$rounds=5000$abcdefghijklmno$abcdefghijklmnopqrstuvwxyz012345');
      expect(c.first.mode, 7400);
    });

    test(r'$6$ → 1800 (sha512crypt)', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$6$rounds=5000$abcdefghijklmno$abcdef');
      expect(c.first.mode, 1800);
    });

    test(r'$P$ → 400 (phpass)', () {
      final c =
          HashIdentifier.fallbackCandidates(r'$P$8abcDEFGHIJKLMNOPQRSTUVWXYZ0123');
      expect(c.first.mode, 400);
    });

    test('WPA*01* → 22000', () {
      final c = HashIdentifier.fallbackCandidates(
          'WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*'
          'f4747f87f9f4*686173686361742d6573736964***');
      expect(c.first.mode, 22000);
    });

    test(r'$pkzip2$ → 多 PKZIP 候选', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$pkzip2$LoremIpsum*$/pkzip2$');
      final modes = c.map((x) => x.mode).toSet();
      expect(modes.contains(17200), true);
      expect(modes.contains(17210), true);
    });

    test(r'$pdf$1* → 10400, $pdf$5* → 10700', () {
      final c1 = HashIdentifier.fallbackCandidates(
          r'$pdf$1*10000*1000*0*abc*0*def*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0*0');
      expect(c1.first.mode, 10400);
      final c5 = HashIdentifier.fallbackCandidates(
          r'$pdf$5*abc*def*ghi*jkl*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0*1*2*3*4*5*6*7*8*9*0');
      expect(c5.first.mode, 10700);
    });

    test('含 2007 → 9400', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$office$*2007*0*128*16*0*abc*def');
      expect(c.first.mode, 9400);
    });

    test(r'$oldoffice$ → 9700/9800 双候选', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$oldoffice$1*abc*def');
      final modes = c.map((x) => x.mode).toSet();
      expect(modes.contains(9700), true);
      expect(modes.contains(9800), true);
    });

    test(r'$7z$ → 11600', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$7z$0$1$0$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ');
      expect(c.first.mode, 11600);
    });

    test(r'$RAR3$ → 12500', () {
      final c =
          HashIdentifier.fallbackCandidates(r'$RAR3$*0*abc*0');
      expect(c.first.mode, 12500);
    });

    test(r'$keepass$*2* → 13400', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$keepass$*2*6000*0*abc');
      expect(c.first.mode, 13400);
    });

    test(r'$keepass$*4* → 34300', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$keepass$*4*6000*0*abc');
      expect(c.first.mode, 34300);
    });

    test(r'$bitcoin$ → 11300', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$bitcoin$96$abc');
      expect(c.first.mode, 11300);
    });

    test(r'$ethereum$ → scrypt/PBKDF2', () {
      final sc = HashIdentifier.fallbackCandidates(
          r'$ethereum$s$abc$def$ghi');
      expect(sc.first.mode, 15700);
      final pb = HashIdentifier.fallbackCandidates(
          r'$ethereum$p$abc$def$ghi');
      expect(pb.first.mode, 15600);
    });

    test(r'$sshng$ → 22911 系列', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$sshng$6$lV$X1$X2$X3$X4$X5');
      expect(c.map((x) => x.mode).toSet().contains(22911), true);
      expect(c.map((x) => x.mode).toSet().contains(22921), true);
    });

    test(r'$bitlocker$ → 22100', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$bitlocker$1$abc$def$ghi');
      expect(c.first.mode, 22100);
    });

    test(r'$truecrypt$ → 29311 系列（不用 6211）', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$truecrypt$100$abc$def$ghi$jkl');
      final modes = c.map((x) => x.mode).toSet();
      // 关键断言：旧 6211 已被废除，新模式 29311 必须入选
      expect(modes.contains(6211), false,
          reason: '6211 在 hashcat 7 已废除');
      expect(modes.contains(29311), true);
    });

    test(r'$veracrypt$ → 29411 系列', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$veracrypt$100$abc$def$ghi$jkl');
      final modes = c.map((x) => x.mode).toSet();
      expect(modes.contains(13711), false,
          reason: '13711 在 hashcat 7 已废除');
      expect(modes.contains(29411), true);
    });

    test('LUKS v1 SHA-1 + AES → 29511', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$luks$1$sha1$aes$xyz');
      expect(c.first.mode, 29511);
    });

    test('LUKS v1 SHA-512 + serpent → 29532', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$luks$1$sha512$serpent$xyz');
      expect(c.first.mode, 29532);
    });

    test('LUKS v2 → 34100（统一 argon2）', () {
      final c = HashIdentifier.fallbackCandidates(
          r'$luks$2$abc$argon2i$xyz');
      expect(c.first.mode, 34100);
    });

    test('32 hex 字符 → MD5 优先（不是 MD4）', () {
      final c = HashIdentifier.fallbackCandidates(
          '5f4dcc3b5aa765d61d8327deb882cf99');
      expect(c.first.mode, 0, reason: '32hex 应优先当作 MD5');
      expect(c.length, greaterThan(1), reason: '至少要有 NTLM/MD4 备选');
    });

    test('40 hex 字符 → SHA1 优先', () {
      final c = HashIdentifier.fallbackCandidates(
          '356a192b3913bf04f0fd7d3c0e6a9b6e5b6c2ddf');
      // 40 hex 的「候选排序」当前是 SHA1 在第一位
      expect(c.first.mode, 100);
    });

    test('64 hex 字符 → SHA-256 优先', () {
      final c = HashIdentifier.fallbackCandidates(
          '6dcd4ce23d88e2ee9568ba546c007c63d9131c1b9bd6c3f9a7c3e0c5e3e3e3e3');
      expect(c.first.mode, 1400);
    });

    test('128 hex 字符 → SHA-512', () {
      final c = HashIdentifier.fallbackCandidates('A' * 128);
      expect(c.first.mode, 1700);
    });

    test('DES(Unix) 13 字符', () {
      final c = HashIdentifier.fallbackCandidates('abcdefghijklm');
      expect(c.first.mode, 1500);
    });

    test('完全认不出的字符串返回空列表', () {
      final c = HashIdentifier.fallbackCandidates('hello world');
      expect(c, isEmpty);
    });
  });

  group('parseIdentifyOutput', () {
    test('解析 hashcat --identify 表格行', () {
      // hashcat --identify 输出形如 "  900 | MD4 | Raw Hash"
      const raw = '''
Hash.Mode....: 0
Hash.Target..: 

The following hash modes match the structure of your input hash:

      900 | MD4                                            | Raw Hash
        0 | MD5                                            | Raw Hash
     1000 | NTLM                                           | Operating System
     2600 | md5(md5(\$pass))                                | Raw Hash
''';
      final c = HashIdentifier.parseIdentifyOutput(raw);
      expect(c.length, 4);
      expect(c[0].mode, 900);
      expect(c[0].name, 'MD4');
      expect(c[0].category, 'Raw Hash');
    });

    test('去重', () {
      const raw = '''
      900 | MD4 | Raw Hash
      900 | MD4 | Raw Hash (dup)
       0 | MD5 | Raw Hash
''';
      final c = HashIdentifier.parseIdentifyOutput(raw);
      expect(c.length, 2);
    });

    test('支持 \\r\\n（hashcat 在 Windows 风格换行）', () {
      const raw =
          '      900 | MD4 | Raw Hash\r\n        0 | MD5 | Raw Hash\r\n';
      final c = HashIdentifier.parseIdentifyOutput(raw);
      expect(c.length, 2);
    });

    test('无匹配项', () {
      final c = HashIdentifier.parseIdentifyOutput('nothing here\n');
      expect(c, isEmpty);
    });
  });

  group('reorderByCommonality', () {
    test('32 hex 输入里 MD5 排第一而非 MD4', () {
      // 模拟 hashcat 原始输出（MD4 在前）
      final raw = HashIdentifier.parseIdentifyOutput('''
      900 | MD4 | Raw Hash
        0 | MD5 | Raw Hash
     1000 | NTLM | Operating System
     2600 | md5(md5(\$pass)) | Raw Hash
''');
      final ordered = HashIdentifier.reorderByCommonality(raw);
      expect(ordered.first.mode, 0, reason: 'MD5 优先于 MD4');
      expect(ordered.length, lessThanOrEqualTo(HashIdentifier.maxCandidates));
    });

    test('候选只有一个时不动', () {
      final raw = HashIdentifier.parseIdentifyOutput('   2500 | WPA-EAPOL | WPA');
      final ordered = HashIdentifier.reorderByCommonality(raw);
      expect(ordered.length, 1);
      expect(ordered.first.mode, 2500);
    });

    test('截断到 maxCandidates（6）', () {
      final raw = List.generate(20, (i) => HashModeCandidate(mode: i, name: 'x$i'));
      final ordered = HashIdentifier.reorderByCommonality(raw);
      expect(ordered.length, HashIdentifier.maxCandidates);
    });
  });

  group('luksMode', () {
    test('v1 SHA-1 AES', () => expect(
        HashIdentifier.luksMode(r'$luks$1$sha1$aes$xyz'), 29511));
    test('v1 SHA-1 serpent', () => expect(
        HashIdentifier.luksMode(r'$luks$1$sha1$serpent$xyz'), 29512));
    test('v1 SHA-1 twofish', () => expect(
        HashIdentifier.luksMode(r'$luks$1$sha1$twofish$xyz'), 29513));
    test('v1 SHA-256 AES', () => expect(
        HashIdentifier.luksMode(r'$luks$1$sha256$aes$xyz'), 29521));
    test('v1 SHA-512 AES', () => expect(
        HashIdentifier.luksMode(r'$luks$1$sha512$aes$xyz'), 29531));
    test('v1 RIPEMD160 AES', () => expect(
        HashIdentifier.luksMode(r'$luks$1$ripemd160$aes$xyz'), 29541));
    test('v2 → 34100', () =>
        expect(HashIdentifier.luksMode(r'$luks$2$argon2i$abc'), 34100));
  });
}