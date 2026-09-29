// MIFARE 分析器界面的冒烟测试。
//
// 这个页面的 widget 代码量不小（标签页、可横向滚动的 DataTable、展开面板），
// 光靠 analyze 只能保证「语法没错」，保证不了「渲染不炸」。这里真的把它 pump
// 起来，并切到第二个标签页，把两个页面的骨架都过一遍。
//
// 运行：cd C:\hashcat_build && flutter test test\mifare_screen_test.dart

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:hashcat_gui/app.dart';
import 'package:hashcat_gui/screens/mifare_screen.dart';
import 'package:hashcat_gui/state/app_state.dart';

/// 直接构造 AppState（不走 create()），避免测试里依赖 SharedPreferences
/// 和运行时目录。这个页面只用到 mifareService 与 isPcMode，够用了。
AppState _state({required bool pcMode}) => AppState(isPcMode: pcMode);

Future<void> _pump(WidgetTester tester,
    {required bool pcMode, String? initialPath}) async {
  await tester.pumpWidget(
    ChangeNotifierProvider<AppState>.value(
      value: _state(pcMode: pcMode),
      child: MaterialApp(
        // 用真实主题，而不是裸 MaterialApp：页面依赖 cardTheme，
        // 用裸主题测出来的外观和实际运行的不是一回事。
        theme: buildHashCrackTheme(Brightness.dark),
        home: MifareScreen(initialPath: initialPath),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  group('MIFARE 分析器界面', () {
    testWidgets('应当正常渲染两个标签页', (tester) async {
      await _pump(tester, pcMode: true);

      expect(find.text('MIFARE 卡片分析器'), findsOneWidget);
      expect(find.text('转储分析'), findsOneWidget);
      expect(find.text('密钥恢复'), findsOneWidget);

      // 标签页 1 的骨架
      expect(find.text('选择卡片转储文件'), findsOneWidget);
      expect(find.text('选择文件'), findsOneWidget);
      // PC 端要提示可以拖拽
      expect(find.text('也可以把文件直接拖到这里'), findsOneWidget);
    });

    testWidgets('切到密钥恢复页应展示用途说明与安全提醒', (tester) async {
      await _pump(tester, pcMode: true);

      await tester.tap(find.text('密钥恢复'));
      await tester.pumpAndSettle();

      expect(find.text('这个功能靠什么成立'), findsOneWidget);
      expect(find.text('选择 nonce 日志'), findsOneWidget);
      expect(find.text('请只用于你自己拥有或已获授权的卡片。'), findsOneWidget);
      // 说明里必须点出 mfkey32 这个关键路径
      expect(
        find.textContaining('mfkey32'),
        findsWidgets,
        reason: '要告诉用户这个功能依赖 mfkey32 采集的 nonce',
      );
    });

    testWidgets('手机端不应出现拖拽提示（没有拖拽能力）', (tester) async {
      await _pump(tester, pcMode: false);
      expect(find.text('也可以把文件直接拖到这里'), findsNothing);
      expect(find.text('选择卡片转储文件'), findsOneWidget);
    });

    testWidgets('传入了 nonce 日志路径时应直接落在密钥恢复页', (tester) async {
      // 初始化时会尝试解析一个不存在的文件，走失败分支即可，
      // 这里只验证「自动切到第二个标签页」这个导航行为。
      await _pump(tester, pcMode: true, initialPath: r'C:\x\mfkey32.log');
      await tester.pumpAndSettle();

      expect(find.text('这个功能靠什么成立'), findsOneWidget,
          reason: '带 mfkey32 路径进来时应当直接打开密钥恢复页');
    });

    testWidgets('解析失败时应展示错误信息而不是白屏', (tester) async {
      // 注意：解析要走真实的文件系统，而 testWidgets 默认在 fake async 区域里
      // 跑，真实 I/O 的 Future 永远不会完成。必须用 runAsync 把它放出来。
      await tester.runAsync(() async {
        await tester.pumpWidget(
          ChangeNotifierProvider<AppState>.value(
            value: _state(pcMode: true),
            child: MaterialApp(
              theme: buildHashCrackTheme(Brightness.dark),
              home: const MifareScreen(initialPath: r'C:\x\missing.nfc'),
            ),
          ),
        );
        await tester.pump();
        // 给 exists() 这类真实异步调用留出完成时间
        await Future<void>.delayed(const Duration(milliseconds: 400));
      });
      await tester.pumpAndSettle();

      // 文件不存在 -> MifareParseException -> 错误框里应有可读文字
      expect(find.textContaining('文件不存在'), findsOneWidget);
      // 页面其余部分仍然正常，不是白屏
      expect(find.text('选择卡片转储文件'), findsOneWidget);
    });
  });
}
