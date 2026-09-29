import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/services/hashcat_service.dart';

void main() {
  test('从真实 hashcat 输出中抠出状态 JSON', () {
    final f = File(r'C:\Users\13784\AppData\Local\Temp\hc_out.bin');
    if (!f.existsSync()) {
      // 样本不存在时跳过，避免污染 CI
      return;
    }
    final raw = f.readAsStringSync();

    final found = <Map<String, dynamic>>[];
    final ex = StatusJsonExtractor(onObject: found.add);

    // 模拟真实流式输入：按小块喂，且故意在 JSON 中间切断
    const step = 97;
    for (var i = 0; i < raw.length; i += step) {
      ex.feed(raw.substring(i, i + step > raw.length ? raw.length : i + step));
    }

    expect(found, isNotEmpty, reason: '必须至少解析出一个状态对象');

    final m = found.first;
    expect(m['session'], isNotNull);
    expect(m['progress'], isA<List>());
    expect(m['devices'], isA<List>());

    // 验证关键字段能被正确取出
    final progress = m['progress'] as List;
    expect(progress.length, greaterThanOrEqualTo(2));
    expect((progress[1] as num).toInt(), greaterThan(0));

    int speedHs = 0;
    for (final d in m['devices'] as List) {
      if (d is Map) speedHs += (d['speed'] as num?)?.toInt() ?? 0;
    }
    expect(speedHs, greaterThan(0), reason: '应能从 devices 里累加出速度');
  });

  test('JSON 被交互提示符粘住时仍能解析', () {
    // 这正是导致界面「卡住没反应」的真实形态：
    // 提示符 + 空格填充 + \r + 单行 JSON 挤在同一个 \n 行里
    const chunk =
        '[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => '
        '\r                              \r'
        '{ "session": "t", "status": 1, "progress": [5, 10], '
        '"devices": [ { "speed": 5000 } ], "estimated_stop": 0 }\r\n';

    final found = <Map<String, dynamic>>[];
    StatusJsonExtractor(onObject: found.add).feed(chunk);

    expect(found.length, 1);
    expect(found.first['status'], 1);
    expect((found.first['progress'] as List)[0], 5);
  });

  test('字符串字面量里的花括号不会破坏平衡', () {
    // 哈希值里带括号是常见情况（例如某些 Office / PDF 哈希）
    const chunk = '{"target":"a{b}c}","status":4,"progress":[1,2]}';
    final found = <Map<String, dynamic>>[];
    StatusJsonExtractor(onObject: found.add).feed(chunk);

    expect(found.length, 1);
    expect(found.first['target'], 'a{b}c}');
  });
}
