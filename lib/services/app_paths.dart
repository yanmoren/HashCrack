import 'dart:io';

/// 便携化路径解析层
///
/// 设计目标：软件拷贝到任意电脑、任意目录都能直接运行，不依赖任何写死的
/// 绝对路径（D:\app\...、E:\临时文件\... 之类一律不许出现）。
///
/// 所有运行时依赖（hashcat 内核、Python 运行时、提取工具、字典）统一放在
/// 可执行文件同级的 `runtime/` 目录下，这里负责把它找出来。
///
/// 查找顺序：
///   1. 环境变量 HASHCRACK_RUNTIME（便于调试和自定义部署）
///   2. 从可执行文件所在目录开始，逐级向上找 `runtime/`（兼容发布目录
///      与开发调试目录：build/windows/x64/runner/Debug → 项目根）
///   3. 当前工作目录
///   4. 找不到就返回空串，由调用方给出友好提示
class AppPaths {
  static String? _runtimeRoot;

  /// runtime 目录名
  static const String _runtimeDirName = 'runtime';

  /// 最多向上回溯几级目录
  static const int _maxLevelsUp = 8;

  /// runtime 根目录；找不到时返回空串
  static String get runtimeRoot => _runtimeRoot ??= _resolveRuntimeRoot();

  /// runtime 目录是否可用
  static bool get isAvailable => runtimeRoot.isNotEmpty;

  /// hashcat 可执行文件路径
  static String get hashcatExe {
    if (!isAvailable) return '';
    final name = Platform.isWindows ? 'hashcat.exe' : 'hashcat.bin';
    final p = '$runtimeRoot${Platform.pathSeparator}hashcat${Platform.pathSeparator}$name';
    if (File(p).existsSync()) return p;
    // 兼容：直接放在 runtime 根下
    final alt = '$runtimeRoot${Platform.pathSeparator}$name';
    return File(alt).existsSync() ? alt : p;
  }

  /// hashcat 所在目录（作为工作目录，保证 OpenCL/ modules/ 能被找到）
  static String get hashcatDir {
    final exe = hashcatExe;
    return exe.isEmpty ? '' : File(exe).parent.path;
  }

  /// 内置便携 Python 可执行文件路径（用于运行 zip2john 等提取脚本）
  static String get pythonExe {
    if (!isAvailable) return '';
    for (final name in ['python.exe', 'python3.exe', 'python']) {
      final p = '$runtimeRoot${Platform.pathSeparator}python${Platform.pathSeparator}$name';
      if (File(p).existsSync()) return p;
    }
    return '';
  }

  /// 是否有内置 Python（有就不需要用户装 Python）
  static bool get hasBundledPython => pythonExe.isNotEmpty;

  /// 哈希提取工具目录（zip2john.py / pdf2john.py / office2john.py ...）
  static String get toolsDir {
    if (!isAvailable) return '';
    return '$runtimeRoot${Platform.pathSeparator}tools';
  }

  /// hcxtools 目录（hcxpcapngtool.exe 及其 DLL）
  static String get hcxToolsDir {
    if (!isAvailable) return '';
    return '$toolsDir${Platform.pathSeparator}hcxtools';
  }

  /// hashcat 自带的转换工具目录（`hashcat/tools/*2hashcat.py`）。
  ///
  /// 这些是 hashcat 官方随包发布的提取器（BitLocker / LUKS / VeraCrypt /
  /// MetaMask / VirtualBox…），比第三方脚本更可信，所以直接就地复用，
  /// 不往 runtime/tools 里再拷一份，避免两处版本不一致。
  static String get hashcatToolsDir {
    final dir = hashcatDir;
    if (dir.isEmpty) return '';
    final p = '$dir${Platform.pathSeparator}tools';
    return Directory(p).existsSync() ? p : '';
  }

  /// hcxpcapngtool 可执行文件（WiFi 握手包 → 22000 格式哈希）
  static String get hcxpcapngtoolExe {
    if (!isAvailable) return '';
    final name = Platform.isWindows ? 'hcxpcapngtool.exe' : 'hcxpcapngtool';
    for (final dir in [hcxToolsDir, toolsDir]) {
      final p = '$dir${Platform.pathSeparator}$name';
      if (File(p).existsSync()) return p;
    }
    return '';
  }

  /// 字典目录（用户可以直接往这里丢自己的 .txt 字典）
  static String get dictsDir {
    if (!isAvailable) return '';
    return '$runtimeRoot${Platform.pathSeparator}dicts';
  }

  /// 内置 7-Zip 目录（7z.exe / 7z.dll / License.txt）
  static String get sevenZipDir {
    if (!isAvailable) return '';
    return '$toolsDir${Platform.pathSeparator}7zip';
  }

  /// 内置 7-Zip 可执行文件——压缩包的解压引擎。
  ///
  /// **只认内置**：软件不在用户机器上联网获取二进制，
  /// 也不借用系统已安装的 7-Zip。系统装没装、装的是哪个版本都不可控，
  /// 那会让"同一份包在别人电脑上行为不一样"变成无从复现的偶发问题。
  static String get sevenZipExe {
    if (!isAvailable) return '';
    final name = Platform.isWindows ? '7z.exe' : '7z';
    for (final dir in [sevenZipDir, toolsDir]) {
      if (dir.isEmpty) continue;
      final p = '$dir${Platform.pathSeparator}$name';
      if (File(p).existsSync()) return p;
    }
    return '';
  }

  /// 是否具备解压能力（内置 7-Zip 到位）
  static bool get hasBundled7Zip => sevenZipExe.isNotEmpty;

  /// 供 UI 展示的诊断信息
  static String describe() {
    if (!isAvailable) {
      return '未找到 runtime 目录。请把软件完整解压后再运行，'
          '确保 HashCrack.exe 同级存在 runtime 文件夹。';
    }
    final buf = StringBuffer();
    buf.writeln('runtime 目录: $runtimeRoot');
    buf.writeln('hashcat: ${hashcatExe.isEmpty ? "未找到" : hashcatExe}');
    buf.writeln('Python: ${pythonExe.isEmpty ? "未内置（将尝试系统 Python）" : pythonExe}');
    buf.writeln('提取工具: $toolsDir');
    buf.writeln('字典目录: $dictsDir');
    buf.writeln('hcxpcapngtool: ${hcxpcapngtoolExe.isEmpty ? "未提供（WiFi 功能不可用）" : "已就绪"}');
    return buf.toString();
  }

  static String _resolveRuntimeRoot() {
    // 1) 环境变量显式指定
    final env = Platform.environment['HASHCRACK_RUNTIME'];
    if (env != null && env.isNotEmpty && _looksLikeRuntime(env)) {
      return Directory(env).absolute.path;
    }

    // 2) 可执行文件所在目录逐级向上
    String? exeDir;
    try {
      exeDir = File(Platform.resolvedExecutable).parent.absolute.path;
    } catch (_) {}
    if (exeDir != null) {
      final found = _searchUpwards(exeDir);
      if (found != null) return found;
    }

    // 3) 当前工作目录逐级向上
    try {
      final found = _searchUpwards(Directory.current.absolute.path);
      if (found != null) return found;
    } catch (_) {}

    return '';
  }

  static String? _searchUpwards(String startDir) {
    Directory dir = Directory(startDir);
    for (int i = 0; i < _maxLevelsUp; i++) {
      final candidate =
          '${dir.path}${Platform.pathSeparator}$_runtimeDirName';
      if (_looksLikeRuntime(candidate)) {
        return Directory(candidate).absolute.path;
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
    return null;
  }

  /// 判断一个目录是否像是我们打包的 runtime 目录
  static bool _looksLikeRuntime(String path) {
    try {
      final d = Directory(path);
      if (!d.existsSync()) return false;
      // 有 hashcat 或 tools 任意一个就算命中
      if (Directory('$path${Platform.pathSeparator}hashcat').existsSync()) {
        return true;
      }
      if (Directory('$path${Platform.pathSeparator}tools').existsSync()) {
        return true;
      }
    } catch (_) {}
    return false;
  }
}
