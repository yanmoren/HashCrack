// 验证应用内 ExtractorService 的 WiFi / ZIP 提取链路，并做端到端破解断言。
// 运行：cd C:\hashcat_build && flutter test test\extractor_wifi_test.dart
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/file_type.dart';
import 'package:hashcat_gui/services/extractor_service.dart';

const rt = r'C:\portable_test\HashCrack\runtime';
const fl = rt + r'\hashcat\hashcat.exe';

void main() {
  final svc = ExtractorService(
    toolsDir: rt + r'\tools',
    pythonPath: rt + r'\python\python.exe',
    onLog: (s) => print('   [log] $s'),
  );

  test('WiFi 握手包 -> 22000 且能用真实密码破出', () async {
    final r = await svc.extract(
        r'C:\hashcat_build\t2\handshake_firework.pcap',
        DetectedFileType.wifiPcap);
    print('success=${r.success} hashType=${r.hashType}');
    print('hash=${r.hash}');
    if (r.error.isNotEmpty) print('error=${r.error}');
    expect(r.success, isTrue, reason: r.error);
    expect(r.hashType, 22000);
    expect(r.hash, startsWith('WPA*02*'),
        reason: '类型字段必须是 02(EAPOL)，01 会被当 PMKID 处理');

    // EAPOL 字段里的 MIC 必须已置零（内核对这段字节直接做 HMAC）
    final parts = r.hash.split('*');
    final eapol = parts[7];
    expect(eapol.substring(81 * 2, 97 * 2), '0' * 32,
        reason: 'EAPOL 字段的 MIC 必须置零，否则永远算不出正确 MIC');

    // 端到端：用真实密码跑 hashcat，必须破解
    final dir = Directory(r'C:\hashcat_build\t2\_wt')
      ..createSync(recursive: true);
    final hf = File('${dir.path}\\w.22000')..writeAsStringSync(r.hash + '\n');
    final wl = File('${dir.path}\\p.txt')..writeAsStringSync('z419372190\n');
    final out = File('${dir.path}\\out.txt')..writeAsStringSync('');
    final pr = await Process.run(
      fl,
      [
        '-m', '22000', '-a', '0', hf.path, wl.path,
        '--potfile-disable', '-w', '3',
        '--session', 'wifitest',
        '--outfile', out.path, '--outfile-format', '2',
      ],
      // hashcat 从 cwd 找 ./OpenCL，必须以自身目录为工作目录
      workingDirectory: File(fl).parent.path,
    );
    print((pr.stdout as String).split('\n')
        .where((l) => l.contains('Status') || l.contains('Recovered'))
        .join('\n'));
    final recovered = out.readAsStringSync().trim();
    print('recovered=$recovered');
    expect(recovered, contains('z419372190'), reason: '应破出真实的 WiFi 密码');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('ZipCrypto 大包（4.8GB）-> 17200', () async {
    final sw = Stopwatch()..start();
    final r = await svc.extract(
        r'E:\临时文件\Photoshop 2024 专业版win.zip', DetectedFileType.zip);
    sw.stop();
    print('elapsed=${sw.elapsedMilliseconds}ms success=${r.success} type=${r.hashType}');
    print('hash=${r.hash.substring(0, r.hash.length > 160 ? 160 : r.hash.length)}');
    if (r.error.isNotEmpty) print('error=${r.error}');
    expect(r.success, isTrue, reason: r.error);
    expect(sw.elapsedMilliseconds, lessThan(20000),
        reason: '应使用 mmap，不应整体读入 4.8GB');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
