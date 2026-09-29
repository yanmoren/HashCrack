import 'dart:io';

class DictEntry {
  final String path;
  final String name;
  final int sizeBytes;
  final bool builtIn;

  const DictEntry({
    required this.path,
    required this.name,
    this.sizeBytes = 0,
    this.builtIn = false,
  });

  String get sizeLabel {
    if (sizeBytes < 1024) return '$sizeBytes B';
    if (sizeBytes < 1024 * 1024) return '${(sizeBytes / 1024).toStringAsFixed(1)} KB';
    return '${(sizeBytes / 1024 / 1024).toStringAsFixed(1)} MB';
  }
}

/// 字典管理
///
/// 字典来源（按顺序）：
///   1. 软件自带目录 runtime\dicts  —— 用户可以直接往这里丢 .txt 字典文件，
///      软件启动时自动扫描，无需在界面里逐个添加
///   2. 工作目录里的字典（历史兼容）
///   3. 用户在界面里手动添加的用户字典
///
/// 这样设计是为了"零配置上手"：把常用字典往 runtime\dicts 里一放就能用。
class DictService {
  final String workDir;
  final String assetsDictsDir;

  /// 便携目录下的字典目录（runtime\dicts）
  final String portableDictsDir;

  final List<String> userDicts;
  String? hashcatDir;

  DictService({
    required this.workDir,
    required this.assetsDictsDir,
    this.portableDictsDir = '',
    this.userDicts = const [],
    this.hashcatDir,
  });

  Future<List<DictEntry>> listDicts() async {
    final entries = <DictEntry>[];
    final seen = <String>{};

    Future<void> scanDir(String dir, String prefix, bool builtIn) async {
      if (dir.isEmpty) return;
      final d = Directory(dir);
      if (!await d.exists()) return;
      await for (final e in d.list()) {
        if (e is! File) continue;
        final name = e.uri.pathSegments.last;
        // 只收文本文件，跳过隐藏文件和说明文件
        if (name.startsWith('.')) continue;
        if (!_isDictFile(name)) continue;
        final path = e.absolute.path;
        if (!seen.add(path)) continue;
        entries.add(DictEntry(
          path: path,
          name: '$prefix$name',
          sizeBytes: await e.length(),
          builtIn: builtIn,
        ));
      }
    }

    // 1) 便携目录字典（用户可自由增删）
    await scanDir(portableDictsDir, '内置 · ', true);
    // 2) 工作目录字典（历史兼容）
    await scanDir('$workDir${Platform.pathSeparator}dicts', '内置 · ', true);

    // 3) hashcat 自带示例字典（如果打包时保留了）
    if (hashcatDir != null) {
      final exampleDict = File('$hashcatDir${Platform.pathSeparator}example.dict');
      if (await exampleDict.exists() && seen.add(exampleDict.absolute.path)) {
        entries.add(DictEntry(
          path: exampleDict.absolute.path,
          name: 'hashcat · example.dict',
          sizeBytes: await exampleDict.length(),
          builtIn: true,
        ));
      }
    }

    // 4) 用户手动添加的字典
    for (final p in userDicts) {
      final f = File(p);
      if (await f.exists() && seen.add(f.absolute.path)) {
        entries.add(DictEntry(
          path: f.absolute.path,
          name: '用户 · ${p.split(Platform.pathSeparator).last}',
          sizeBytes: await f.length(),
          builtIn: false,
        ));
      }
    }
    return entries;
  }

  bool _isDictFile(String name) {
    final lower = name.toLowerCase();
    return lower.endsWith('.txt') ||
        lower.endsWith('.dic') ||
        lower.endsWith('.dict') ||
        lower.endsWith('.lst') ||
        lower.endsWith('.wordlist');
  }

  /// 兼容旧调用：内置字典现在直接放 runtime\dicts，无需再拷贝
  Future<void> ensureBuiltInDict() async {
    if (portableDictsDir.isNotEmpty) {
      await Directory(portableDictsDir).create(recursive: true);
      return;
    }
    final builtinDir = Directory('$workDir${Platform.pathSeparator}dicts');
    await builtinDir.create(recursive: true);
    final src = File(assetsDictsDir);
    final dst = File('${builtinDir.path}${Platform.pathSeparator}common.txt');
    if (await src.exists() && !await dst.exists()) {
      await src.copy(dst.path);
    }
  }

  Future<void> addUserDict(String path) async {
    if (!userDicts.contains(path)) {
      userDicts.add(path);
    }
  }

  List<String> get activeDictPaths => userDicts;
}
