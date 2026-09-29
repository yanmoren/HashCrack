// 暴力破解配置面板（BruteForceSheet）的 UI 验证。
// 目的是在不手动点鼠标的前提下确认：推荐预设被正确选中、组合空间与预计耗时
// 真的渲染出来、超长耗时给出告警、以及「开始破解」返回的配置是对的。
//
// 运行：cd C:\hashcat_build && flutter test test\brute_force_sheet_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hashcat_gui/models/brute_force.dart';
import 'package:hashcat_gui/models/task.dart';
import 'package:hashcat_gui/widgets/brute_force_sheet.dart';

CrackTask wifiTask({int speedKhs = 8600}) => CrackTask(
      id: 't1',
      filePath: r'C:\x\handshake.pcap',
      fileName: 'handshake.pcap',
      hashType: 22000,
      hashValue: 'WPA*02*aa*bb*cc*dd*ee*ff*00',
      // 8.6 k/s，接近真实 WPA 在普通机器上的量级
      speedKhs: speedKhs,
      createdAt: DateTime(2026, 9, 11),
    );

void main() {
  /// 面板很高，默认 800x600 的测试画布会把按钮挤出可视区，
  /// 导致 tap 报 "not visible"。直接把画布调大。
  Future<void> setLargeSurface(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1200, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
  }

  /// 起一个带按钮的页面，点开后把面板返回的配置写到 [result] 里。
  Future<void> pumpAndOpen(WidgetTester tester, CrackTask task,
      void Function(BruteForceConfig?) result) async {
    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (ctx) => Scaffold(
          body: Center(
            child: ElevatedButton(
              onPressed: () async {
                result(await showBruteForceSheet(ctx, task: task));
              },
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
  }

  testWidgets('WiFi 任务默认选中「纯数字 8 位」并显示组合空间与耗时', (tester) async {
    await setLargeSurface(tester);
    BruteForceConfig? cfg;
    await pumpAndOpen(tester, wifiTask(), (v) => cfg = v);

    // 默认预设 = 22000 的第一个推荐（8 位纯数字 = 1 亿）
    expect(find.text('纯数字 8 位'), findsWidgets);
    expect(find.text('组合空间'), findsOneWidget);
    expect(find.text('预计耗时'), findsOneWidget);
    expect(find.text('1 亿'), findsWidgets);
    expect(find.text('不限时'), findsWidgets);
    expect(find.text('开始破解'), findsOneWidget);

    await tester.tap(find.text('开始破解'));
    await tester.pumpAndSettle();

    expect(cfg, isNotNull);
    expect(cfg!.charset, CharsetPreset.digits);
    expect(cfg!.minLen, 8);
    expect(cfg!.maxLen, 8);
    // 默认不限时——慢哈希不这样根本跑不完
    expect(cfg!.runtimeSec, 0);
  });

  testWidgets('改成「小写+数字 8 位」后空间暴涨，应给出过大告警', (tester) async {
    await setLargeSurface(tester);
    BruteForceConfig? cfg;
    await pumpAndOpen(tester, wifiTask(), (v) => cfg = v);

    await tester.tap(find.text('小写+数字（a-z0-9）'));
    await tester.pumpAndSettle();

    // 36^8 = 2.82 万亿；8.6 k/s 要按天算 → 必须红字告警，
    // 不能让用户以为点一下就能出结果
    expect(find.text('2.82 万亿'), findsWidgets);
    expect(find.textContaining('这个空间太大'), findsOneWidget);

    await tester.tap(find.text('10 分钟'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('开始破解'));
    await tester.pumpAndSettle();

    expect(cfg, isNotNull);
    expect(cfg!.charset, CharsetPreset.lowerDigit);
    expect(cfg!.minLen, 8);
    expect(cfg!.maxLen, 8);
    expect(cfg!.runtimeSec, 600);
  });

  testWidgets('手动加减长度会切成「自定义」，组合空间随之变化', (tester) async {
    await setLargeSurface(tester);
    BruteForceConfig? cfg;
    await pumpAndOpen(tester, wifiTask(), (v) => cfg = v);

    // 默认选中第一个推荐（8 位）。点最长那一栏的「+」改到 9 → 10^8 + 10^9
    final plus = find.byIcon(Icons.add);
    expect(plus, findsNWidgets(2));
    await tester.tap(plus.last);
    await tester.pumpAndSettle();

    // 区间变成 8-9 位，组合空间应变成 11 亿
    expect(find.text('11 亿'), findsWidgets);

    await tester.tap(find.text('开始破解'));
    await tester.pumpAndSettle();

    expect(cfg, isNotNull);
    expect(cfg!.charset, CharsetPreset.digits);
    expect(cfg!.minLen, 8);
    expect(cfg!.maxLen, 9);
    expect(cfg!.keyspace, BigInt.from(1100000000));
  });
}
