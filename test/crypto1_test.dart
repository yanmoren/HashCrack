// Crypto1 / Crapto1 移植的回归测试。
//
// 这个算法没有「差不多对」的中间态：LFSR 只差一位，恢复出来的密钥就完全不同。
// 所以这里做了三层锁定：
//   1. 公开测试向量 —— 一份业界通用的 mfkey32 样例，预期 Key A = A0A1A2A3A4A5
//   2. 往返自证 —— 用同一套算法正向造出 nonce，再反向恢复，必须回到原密钥
//   3. 篡改拒绝 —— 改动一个 nonce，必须恢复失败（返回 null）而不是返回错密钥
//
// 第 3 条尤其重要：它保证了「能算出密钥」这件事是有判据的，而不是碰巧蒙对。

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/utils/crypto1.dart';

int _u32(int x) => x & 0xFFFFFFFF;

/// 用给定密钥正向跑一次完整的 mfkey32 认证流程，造出可被恢复的 nonce 组。
///
/// MIFARE Classic 的认证握手（读卡器 ↔ 卡片）：
///   1. 读卡器发 `uid ^ nt`（明文），LFSR 以明文回馈
///   2. 卡片回 `{nr}`（加密的读卡器随机数）
///   3. 读卡器再发 `{ar}`，卡片用 `nt` 经 PRNG 推进 64 位得到 `nt'`，
///      校验 `{ar} ^ nt'` 是否等于自己算出的密钥流
///
/// 关键点：LFSR 在这条通路上**以明文回馈**，所以造向量时必须用
/// `crypto1EncryptWord`（喂明文、返回密文）而不是 `crypto1Word(..., 1)`
/// （那个返回的是密钥流，还得再异或一次）。
Map<String, int> _makeVector({
  required int key,
  required int uid,
  required int nt0,
  required int nr0,
  required int nt1,
  required int nr1,
}) {
  final s0 = crypto1Init(key);
  crypto1Word(s0, _u32(uid ^ nt0), 0);
  final nr0Enc = crypto1EncryptWord(s0, _u32(nr0));
  final ar0Enc = _u32(crypto1Word(s0, 0, 0) ^ prngSuccessor(_u32(nt0), 64));

  final s1 = crypto1Init(key);
  crypto1Word(s1, _u32(uid ^ nt1), 0);
  final nr1Enc = crypto1EncryptWord(s1, _u32(nr1));
  final ar1Enc = _u32(crypto1Word(s1, 0, 0) ^ prngSuccessor(_u32(nt1), 64));

  return {
    'uid': _u32(uid),
    'nt0': _u32(nt0),
    'nr0': nr0Enc,
    'ar0': ar0Enc,
    'nt1': _u32(nt1),
    'nr1': nr1Enc,
    'ar1': ar1Enc,
  };
}

int? _recover(Map<String, int> v) => recoverMifareKeyFromNonces(
      uid: v['uid']!,
      nt0: v['nt0']!,
      nr0Enc: v['nr0']!,
      ar0Enc: v['ar0']!,
      nt1: v['nt1']!,
      nr1Enc: v['nr1']!,
      ar1Enc: v['ar1']!,
    );

void main() {
  group('Crypto1 基础件', () {
    test('crypto1Init + crypto1GetLfsr 应当互为逆运算', () {
      for (final key in [
        0xA0A1A2A3A4A5,
        0xFFFFFFFFFFFF,
        0x000000000000,
        0x1234567890AB,
        0x000000000001,
      ]) {
        final state = crypto1Init(key);
        expect(crypto1GetLfsr(state), key,
            reason: '密钥 ${formatMifareKey(key)} 经过 LFSR 初始化后应能原样取回');
      }
    });

    test('prngSuccessor 是确定性的，且推进 0 位等于原值', () {
      expect(prngSuccessor(0x12345678, 0), 0x12345678);
      final a = prngSuccessor(0x12345678, 64);
      final b = prngSuccessor(0x12345678, 64);
      expect(a, b, reason: '同样的输入必须得到同样的输出');
      expect(a, isNot(0x12345678), reason: '推进 64 位后应当发生变化');
    });
  });

  group('mfkey32 密钥恢复', () {
    test('公开测试向量应恢复出 A0A1A2A3A4A5', () {
      // 业界通用的 mfkey32 样例向量
      final key = recoverMifareKeyFromNonces(
        uid: 0x2A234F80,
        nt0: 0x240BD022,
        nr0Enc: 0xAD2E1687,
        ar0Enc: 0x57E6F7E4,
        nt1: 0x18A4BD3E,
        nr1Enc: 0xACCC1A23,
        ar1Enc: 0x6F10E401,
      );
      expect(key, isNotNull, reason: '公开向量必须能恢复出密钥');
      expect(formatMifareKey(key!), 'A0A1A2A3A4A5');
    });

    test('真实卡 UID 与多组密钥的往返恢复全部命中', () {
      // 用用户那张 Dtk 转储里的真实 UID，覆盖出厂值、全 0、全 F、手工值等典型密钥
      const uid = 0xD2377202;
      const cases = <int, String>{
        0xA0A1A2A3A4A5: 'NXP 演示 Key A',
        0xFFFFFFFFFFFF: 'NXP 出厂默认',
        0x1234567890AB: '常见手工配置',
        0x000000000001: '边界值（最低位为 1）',
        0x000000000000: '全 0 边界值',
        0x4D3A99C351DD: '常见公开默认',
      };

      for (final entry in cases.entries) {
        final v = _makeVector(
          key: entry.key,
          uid: uid,
          nt0: 0x0A1B2C3D,
          nr0: 0x55667788,
          nt1: 0x99AABBCC,
          nr1: 0xDDEEFF11,
        );
        final got = _recover(v);
        expect(got, isNotNull, reason: '${entry.value} 应当能恢复出来');
        expect(formatMifareKey(got!), formatMifareKey(entry.key),
            reason: '${entry.value} 恢复结果应与原密钥一致');
      }
    });

    test('每次换一组随机数都应恢复出同一个密钥', () {
      const key = 0xABCD12345678;
      const uid = 0xD2377202;
      for (var i = 0; i < 5; i++) {
        final v = _makeVector(
          key: key,
          uid: uid,
          nt0: 0x11111111 + i * 0x01010101,
          nr0: 0x22222222 + i * 0x02020202,
          nt1: 0x33333333 + i * 0x03030303,
          nr1: 0x44444444 + i * 0x04040404,
        );
        final got = _recover(v);
        expect(got, isNotNull, reason: '第 $i 组随机数应当能恢复');
        expect(formatMifareKey(got!), 'ABCD12345678');
      }
    });

    test('篡改第二次会话的 {ar} 必须恢复失败而不是给出错误密钥', () {
      final v = _makeVector(
        key: 0xA0A1A2A3A4A5,
        uid: 0xD2377202,
        nt0: 0x0A1B2C3D,
        nr0: 0x55667788,
        nt1: 0x99AABBCC,
        nr1: 0xDDEEFF11,
      );
      v['ar1'] = _u32(v['ar1']! ^ 0x00000001); // 翻转一位
      expect(_recover(v), isNull,
          reason: '校验位对不上时必须判定失败，绝不允许返回一个「像样」的错密钥');
    });

    test('两组 nonce 来自不同卡片（UID 不匹配）也必须失败', () {
      const key = 0xA0A1A2A3A4A5;
      final a = _makeVector(
        key: key,
        uid: 0x11111111,
        nt0: 0x0A1B2C3D,
        nr0: 0x55667788,
        nt1: 0x99AABBCC,
        nr1: 0xDDEEFF11,
      );
      final b = _makeVector(
        key: key,
        uid: 0x22222222,
        nt0: 0x0A1B2C3D,
        nr0: 0x55667788,
        nt1: 0x99AABBCC,
        nr1: 0xDDEEFF11,
      );
      expect(_recover({
        ...a,
        'ar1': b['ar1']!,
        'nr1': b['nr1']!,
      }), isNull, reason: '跨卡片的 nonce 拼不出正确密钥');
    });
  });

  group('密钥格式化', () {
    test('应当输出 12 位大写十六进制并补齐前导零', () {
      expect(formatMifareKey(0xA0A1A2A3A4A5), 'A0A1A2A3A4A5');
      expect(formatMifareKey(0), '000000000000');
      expect(formatMifareKey(1), '000000000001');
      expect(formatMifareKey(0xFFFFFFFFFFFF), 'FFFFFFFFFFFF');
    });
  });
}
