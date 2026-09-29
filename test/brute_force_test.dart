// 暴力破解策略验证。
//
// 分两层：
//   1) 纯逻辑单测（不依赖 hashcat）：掩码组合空间、长度区间、参数拼装、格式化
//   2) 端到端：用应用自己的 HashcatService.runBruteForce 跑真实 hashcat，
//      对一个密码已知的 ZipCrypto 样本（Bandizip 生成，密码 48217）做穷举，
//      必须破出，并且阶段回调、速度采集、不限时分支都要走到
//
// 运行：
//   cd C:\hashcat_build
//   HASHCRACK_RUNTIME=C:\portable_test\HashCrack\runtime flutter test test\brute_force_test.dart
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/brute_force.dart';
import 'package:hashcat_gui/models/file_type.dart';
import 'package:hashcat_gui/services/extractor_service.dart';
import 'package:hashcat_gui/services/hashcat_service.dart';

const rt = r'C:\portable_test\HashCrack\runtime';
const fl = rt + r'\hashcat\hashcat.exe';
const sampleZip = r'C:\hashcat_build\t2\bf_test.zip';
const samplePassword = '48217';

void main() {
  // ---------------------------------------------------------------- 纯逻辑
  group('掩码组合空间', () {
    test('单字符集占位符按位相乘', () {
      expect(maskKeyspace('?d'), BigInt.from(10));
      expect(maskKeyspace('?d?d?d'), BigInt.from(1000));
      expect(maskKeyspace('?d?d?d?d?d?d?d?d'), BigInt.from(100000000));
      expect(maskKeyspace('?u?l?l?l?l?l?d?d'),
          BigInt.from(26 * 26 * 26 * 26 * 26 * 26 * 10 * 10));
    });

    test('字面量与转义问号只贡献 1 种可能', () {
      expect(maskKeyspace('abc'), BigInt.one);
      expect(maskKeyspace('??'), BigInt.one);
      expect(maskKeyspace('a?db'), BigInt.from(10));
    });

    test('未知占位符返回 0 表示「无法计算」', () {
      // 界面遇到 0 要显示「—」，不能瞎猜一个数字
      expect(maskKeyspace('?z'), BigInt.zero);
      expect(maskKeyspace('?'), BigInt.zero);
    });
  });

  group('字符集 + 长度区间', () {
    test('组合空间是各长度之和', () {
      const cfg = BruteForceConfig(
          charset: CharsetPreset.digits, minLen: 4, maxLen: 7);
      // 10^4 + 10^5 + 10^6 + 10^7
      expect(cfg.keyspace, BigInt.from(11110000));
      expect(cfg.label, '纯数字 4-7 位');
      // 掩码统一用 ?1 铺满最大长度，靠 --increment 控制实际试探长度
      expect(cfg.mask, '?1?1?1?1?1?1?1');
    });

    test('多字符集必须走 -1，否则会退化成交替掩码', () {
      const cfg = BruteForceConfig(
          charset: CharsetPreset.lowerDigit, minLen: 8, maxLen: 8);
      final args = cfg.optionArgs;
      expect(args, containsAllInOrder(['-1', '?l?d']));
      expect(args, contains('--increment'));
      expect(args, contains('--increment-min=8'));
      expect(args, contains('--increment-max=8'));
      // 36^8
      expect(cfg.keyspace, BigInt.from(2821109907456));
    });

    test('长度会归一化，倒着填也不会算出空区间', () {
      final c = BruteForceConfig.normalized(
          charset: CharsetPreset.digits, minLen: 9, maxLen: 4);
      expect(c.minLen, 4);
      expect(c.maxLen, 9);
      expect(c.keyspace, BruteForceConfig(
              charset: CharsetPreset.digits, minLen: 4, maxLen: 9)
          .keyspace);
    });

    test('WiFi 推荐预设符合 WPA 规范（最短 8 位）', () {
      final p = recommendedBruteForcePresets(22000);
      expect(p, isNotEmpty);
      expect(p.first.charset, CharsetPreset.digits);
      expect(p.first.minLen, 8);
      expect(p.first.maxLen, 8);
      expect(p.first.keyspace, BigInt.from(100000000));
      expect(p.every((c) => c.minLen >= 6), isTrue,
          reason: 'WPA 密码最短 8 位，不该推荐更短的长度');
    });

    test('压缩包预设从 1 位数字起步', () {
      final p = recommendedBruteForcePresets(17200);
      expect(p.first.minLen, 1);
      expect(p.first.maxLen, 8);
    });
  });

  group('可读格式化', () {
    test('组合空间按数量级切换单位', () {
      expect(formatKeyspace(BigInt.from(999)), '999');
      expect(formatKeyspace(BigInt.from(1500)), '1.5 千');
      expect(formatKeyspace(BigInt.from(11110000)), '1111 万');
      expect(formatKeyspace(BigInt.from(100000000)), '1 亿');
      expect(formatKeyspace(BigInt.from(10000000000)), '100 亿');
      expect(formatKeyspace(BigInt.from(2821109907456)), '2.82 万亿');
      expect(formatKeyspace(BigInt.zero), '—');
    });

    test('耗时按量级截断，避免出现「3123456789 秒」', () {
      expect(formatDuration(const Duration(seconds: 45)), '45 秒');
      expect(formatDuration(const Duration(seconds: 90)), '1 分');
      expect(formatDuration(const Duration(hours: 3, minutes: 30)),
          '3 小时 30 分');
      expect(formatDuration(const Duration(days: 2, hours: 5)), '2 天 5 小时');
      expect(formatDuration(const Duration(days: 800)), '2.2 年');
      expect(formatDuration(const Duration(days: 3650000)), '超过一万年');
    });
  });

  // ------------------------------------------------------------ 端到端真实跑
  test('暴力破解端到端：纯数字 1-6 位 increment 穷举，破出 48217', () async {
    // 清掉上一轮遗留的 potfile：runBruteForce 会先查历史记录，
    // 命中就直接返回，那样阶段回调与不限时分支都不会走到，测不出东西
    for (final suffix in ['_hash.txt', '_out.txt', '.potfile', '_bf.log',
      '_bf.restore', '.log']) {
      final f = File('${Directory.systemTemp.path}\\bftest$suffix');
      if (f.existsSync()) f.deleteSync();
    }

    final extractor = ExtractorService(
      toolsDir: rt + r'\tools',
      pythonPath: rt + r'\python\python.exe',
      onLog: (s) => print('   [extract] $s'),
    );
    final ex = await extractor.extract(sampleZip, DetectedFileType.zip);
    print('提取结果: success=${ex.success} type=${ex.hashType}');
    print('哈希: ${ex.hash}');
    expect(ex.success, isTrue, reason: ex.error);
    expect(ex.hashType, 17200);

    final phases = <HashcatPhase>[];
    final svc = HashcatService(
      hashcatPath: fl,
      workDir: rt + r'\work',
      pythonPath: rt + r'\python\python.exe',
      onLog: (l) => print('   [hc] $l'),
      onPhase: (p) {
        phases.add(p);
        print('   [phase] ${p.detail}');
      },
    );

    // 不限时（runtimeSec 默认 0）——慢哈希的暴力破解本来就可能要跑很久，
    // 不能被固定的进程硬超时杀掉
    const cfg = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 1, maxLen: 6);
    print('组合空间: ${formatKeyspace(cfg.keyspace)}');
    expect(cfg.keyspace, BigInt.from(1111110)); // 10^1+…+10^6

    final sw = Stopwatch()..start();
    final r = await svc.runBruteForce(
      hash: ex.hash,
      hashType: ex.hashType,
      config: cfg,
      sessionName: 'bftest',
      sourceFile: sampleZip,
    );
    sw.stop();
    print('cracked=${r.cracked} password=${r.password} '
        'elapsed=${sw.elapsedMilliseconds}ms');
    if (r.error.isNotEmpty) print('error=${r.error}');

    expect(r.cracked, isTrue, reason: r.error);
    expect(r.password, samplePassword);

    // 阶段回调必须带上「暴力破解」标记，否则界面会继续显示「掩码攻击」，
    // 用户分不清是自动流程还是自己发起的穷举
    final bfPhases = phases.where((p) => p.isBruteForce).toList();
    expect(bfPhases, isNotEmpty, reason: '应上报暴力破解阶段');
    expect(bfPhases.first.detail, contains('暴力破解'));
    expect(bfPhases.first.detail, contains('纯数字 1-6 位'));
    expect(bfPhases.first.detail, contains('种组合'));

    // 内部日志（组合空间 / 运行方式 / 完整命令行）都在 result.log 里，
    // onLog 只转发 hashcat 自身的 stdout/stderr
    expect(r.log, contains('组合空间'));
    expect(r.log, contains('运行时限: 不限时'));
    expect(r.log, contains('--increment'));
    expect(r.log, contains('--increment-min=1'));
    expect(r.log, contains('--increment-max=6'));
    expect(r.log, isNot(contains('--runtime=')),
        reason: '不限时不应该出现 --runtime 参数');
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('限时分支：大空间被 --runtime 截断，且候选总数与组合空间逐位一致', () async {
    for (final suffix in [
      '_hash.txt', '_out.txt', '.potfile', '_bf.log', '_bf.restore', '.log'
    ]) {
      final f = File('${Directory.systemTemp.path}\\bftest2$suffix');
      if (f.existsSync()) f.deleteSync();
    }

    final extractor = ExtractorService(
      toolsDir: rt + r'\tools',
      pythonPath: rt + r'\python\python.exe',
    );
    final ex = await extractor.extract(sampleZip, DetectedFileType.zip);
    expect(ex.success, isTrue, reason: ex.error);

    BigInt? reportedTotal;
    var maxSpeed = 0;
    final svc = HashcatService(
      hashcatPath: fl,
      workDir: rt + r'\work',
      pythonPath: rt + r'\python\python.exe',
      onProgress: (p) {
        maxSpeed = p.speedKhs > maxSpeed ? p.speedKhs : maxSpeed;
        if (p.totalCount > 0) {
          final t = BigInt.from(p.totalCount);
          if (reportedTotal == null || t > reportedTotal!) reportedTotal = t;
        }
      },
    );

    // 10 位纯数字 = 1e10。17200 大约 1 GH/s，6 秒只能跑一半左右，
    // 必然被 --runtime 截断 —— 正好用来验证限时分支与进度上报。
    const cfg = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 10, maxLen: 10, runtimeSec: 6);
    final r = await svc.runBruteForce(
      hash: ex.hash,
      hashType: ex.hashType,
      config: cfg,
      sessionName: 'bftest2',
      sourceFile: sampleZip,
    );
    print('cracked=${r.cracked} reportedTotal=$reportedTotal '
        'maxSpeed=${maxSpeed}kH/s');
    if (r.error.isNotEmpty) print('error=${r.error}');

    expect(r.cracked, isFalse, reason: '1e10 的空间不可能在 6 秒内跑完');
    expect(r.log, contains('运行时限: 6 秒'));
    expect(r.log, contains('--runtime=6'));
    // 限时截断不能说成「已遍历全部组合」——那会让用户误以为
    // 这个字符集+长度已被证明无效，从而错过真正的密码
    expect(r.error, contains('限时 6 秒已用满'));
    expect(r.error, isNot(contains('全部')));
    expect(r.log, contains('组合空间未跑完'));

    // 关键交叉验证：hashcat 自己上报的候选总数必须等于我们算的组合空间，
    // 否则界面上的「预计耗时」就是错的，会误导用户决策
    expect(reportedTotal, isNotNull, reason: '应采集到进度');
    expect(reportedTotal, cfg.keyspace,
        reason: 'hashcat 上报的 total 应与 BruteForceConfig.keyspace 一致');
    expect(reportedTotal, BigInt.from(10000000000));

    // 速度采集：没有实测速度就无法给出可信的预计耗时
    expect(svc.lastSpeedPerSec, greaterThan(0));
  }, timeout: const Timeout(Duration(minutes: 10)));
}
