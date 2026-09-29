// 回归：暴力破解的「固定前缀」能力。
//
// 覆盖点：
// 1. 前缀拼在掩码最前面（无前缀时行为与旧版完全一致）
// 2. --increment 的上下限要按「前缀占用的位置数」平移
//    （hashcat 把字面前缀也算位置，且从右端截断——不移位会截掉真正要搜的位）
// 3. 前缀不参与穷举，组合空间必须保持不变
// 4. 前缀里的 `?` 要转义成 `??`，否则会被 hashcat 当占位符
// 5. 前缀净化（去控制字符、限长）
import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/brute_force.dart';

void main() {
  test('前缀拼在掩码最前面', () {
    const c = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 9, maxLen: 9, prefix: 'z');
    expect(c.mask, 'z${'?1' * 9}');
  });

  test('无前缀时掩码与旧行为一致', () {
    const c =
        BruteForceConfig(charset: CharsetPreset.digits, minLen: 8, maxLen: 8);
    expect(c.mask, '?1' * 8);
    expect(c.optionArgs, contains('--increment-min=8'));
    expect(c.optionArgs, contains('--increment-max=8'));
  });

  test('increment 上下限按前缀位置数平移', () {
    const c = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 8, maxLen: 10, prefix: 'z');
    // 前缀 1 位 + 8..10 位可变 => 掩码长度 9..11
    expect(c.optionArgs, contains('--increment-min=9'));
    expect(c.optionArgs, contains('--increment-max=11'));
  });

  test('前缀不参与穷举：组合空间不变', () {
    const withPrefix = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 9, maxLen: 9, prefix: 'z');
    const without = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 9, maxLen: 9);
    expect(withPrefix.keyspace, without.keyspace);
    expect(withPrefix.keyspace, BigInt.from(1000000000));
  });

  test('前缀里的 ? 会被转义，且只占一个位置', () {
    const c = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 1, maxLen: 1, prefix: '?d');
    // '??' 是字面量 ?，'d' 是字面量 d，再跟一个 ?1
    expect(c.mask, '??d?1');
    // 前缀 2 个字符 + 1 位可变 = 3
    expect(c.optionArgs, contains('--increment-min=3'));
    expect(c.optionArgs, contains('--increment-max=3'));
  });

  test('normalizePrefix 去空白、去控制字符、限长 32', () {
    expect(BruteForceConfig.normalizePrefix('  z  '), 'z');
    expect(BruteForceConfig.normalizePrefix('a\u0000b\u001fc'), 'abc');
    expect(BruteForceConfig.normalizePrefix('x' * 40).length, 32);
    expect(BruteForceConfig.normalizePrefix(''), '');
  });

  test('label 带上前缀描述', () {
    const c = BruteForceConfig(
        charset: CharsetPreset.digits, minLen: 9, maxLen: 9, prefix: 'z');
    expect(c.label, '前缀 z + 纯数字 9 位');

    const d =
        BruteForceConfig(charset: CharsetPreset.digits, minLen: 9, maxLen: 9);
    expect(d.label, '纯数字 9 位');
  });

  test('normalized 会净化传入的前缀', () {
    final c = BruteForceConfig.normalized(
      charset: CharsetPreset.digits,
      minLen: 9,
      maxLen: 9,
      prefix: ' z\t',
    );
    expect(c.prefix, 'z');
    expect(c.mask, 'z${'?1' * 9}');
  });
}
