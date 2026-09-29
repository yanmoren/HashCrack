import 'package:flutter/material.dart';
import 'screens/home_screen.dart';
import 'screens/mifare_screen.dart';
import 'screens/settings_screen.dart';

class HashCrackApp extends StatelessWidget {
  const HashCrackApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'HashCrack',
      debugShowCheckedModeBanner: false,
      theme: buildHashCrackTheme(Brightness.dark),
      home: const HomeScreen(),
      routes: {
        '/settings': (_) => const SettingsScreen(),
        '/mifare': (_) => const MifareScreen(),
      },
    );
  }
}

/// 应用主题。
///
/// 单独抽成顶层函数，是为了让 widget 测试能拿它来 pump 页面——只用一个裸的
/// MaterialApp 会漏掉 cardTheme 这类设定，页面里取 `cardTheme.color` 会拿到
/// null，测出来的外观和真实运行的不是同一个。
ThemeData buildHashCrackTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final seed = const Color(0xFF00E5FF);
  final bg = dark ? const Color(0xFF0B1020) : const Color(0xFFF4F7FB);
  final card = dark ? const Color(0xFF161C30) : Colors.white;
  final fg = dark ? const Color(0xFFE6EDF6) : const Color(0xFF1A1F2C);
  final muted = dark ? const Color(0xFF7A86A0) : const Color(0xFF6B7488);

  return ThemeData(
    useMaterial3: true,
    brightness: brightness,
    scaffoldBackgroundColor: bg,
    colorScheme: ColorScheme.fromSeed(
      seedColor: seed,
      brightness: brightness,
      primary: seed,
      surface: card,
      onSurface: fg,
    ),
    cardTheme: CardThemeData(
      color: card,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(
          color: dark ? const Color(0xFF2A3350) : const Color(0xFFE3E8F0),
        ),
      ),
    ),
    appBarTheme: AppBarTheme(
      backgroundColor: bg,
      foregroundColor: fg,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        color: fg,
        fontSize: 20,
        fontWeight: FontWeight.w700,
      ),
    ),
    textTheme: TextTheme(
      bodyLarge: TextStyle(color: fg),
      bodyMedium: TextStyle(color: fg),
      bodySmall: TextStyle(color: muted),
      titleLarge: TextStyle(color: fg, fontWeight: FontWeight.w700),
      titleMedium: TextStyle(color: fg, fontWeight: FontWeight.w600),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: dark ? const Color(0xFF1E2640) : const Color(0xFFEFF3F9),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide.none,
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: seed, width: 1.5),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: seed,
        foregroundColor: const Color(0xFF04121A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
      ),
    ),
  );
}
