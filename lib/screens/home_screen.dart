import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:provider/provider.dart';
import '../state/app_state.dart';
import '../models/file_type.dart';
import '../models/task.dart';
import '../services/file_identifier.dart';
import '../widgets/brute_force_sheet.dart';
import '../widgets/drop_zone.dart';
import '../widgets/task_card.dart';
import 'mifare_screen.dart';
import 'result_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _afterFrame());
  }

  void _afterFrame() {
    final state = context.read<AppState>();
    if (state.initError != null) {
      _showSnack('初始化: ${state.initError}');
    }
  }

  Future<void> _onFile(String path) async {
    final state = context.read<AppState>();
    setState(() => _busy = true);
    try {
      // MIFARE 转储和 nonce 日志不走 hashcat：hashcat 完全不认识这类文件
      // （7.x 也没有 MIFARE 模式），硬塞进去只会得到一句「无法识别」。
      // 而且分析在本地就能做完，手机端也不需要连 PC。
      final type = await FileIdentifier.identify(path);
      if (type == DetectedFileType.mifareDump ||
          type == DetectedFileType.nonceLog) {
        if (!mounted) return;
        await Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => MifareScreen(initialPath: path)),
        );
        return;
      }

      if (state.isPcMode) {
        await state.submitLocalFile(path);
      } else {
        if (state.remote == null || !state.remote!.isConfigured) {
          _showSnack('请先在设置里配置 PC 地址');
          return;
        }
        await state.submitRemoteFile(path);
        _showSnack('已上传到 PC，正在处理…');
      }
    } catch (e) {
      _showSnack('提交失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _showSnack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(
        content: Text(msg),
        behavior: SnackBarBehavior.floating,
      ));
  }

  /// 对失败任务发起暴力破解：先让用户看清组合空间与预计耗时再动手。
  Future<void> _startBruteForce(CrackTask task) async {
    final state = context.read<AppState>();
    if (!state.isPcMode &&
        (state.remote == null || !state.remote!.isConfigured)) {
      _showSnack('请先在设置里配置 PC 地址');
      return;
    }
    final cfg = await showBruteForceSheet(context, task: task);
    if (cfg == null || !mounted) return;
    try {
      await state.retryWithBruteForce(task.id, cfg);
      _showSnack('已开始暴力破解：${cfg.label}');
    } catch (e) {
      _showSnack('发起失败: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [accent, accent.withOpacity(0.6)],
                ),
                borderRadius: BorderRadius.circular(9),
              ),
              child: const Icon(Icons.lock,
                  size: 18, color: Colors.black),
            ),
            const SizedBox(width: 10),
            const Text('HashCrack'),
          ],
        ),
        actions: [
          _connChip(state, theme),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => Navigator.pushNamed(context, '/settings'),
          ),
        ],
      ),
      body: state.initialized ? _body(state, theme) : _loading(),
    );
  }

  Widget _loading() => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('初始化中…'),
          ],
        ),
      );

  Widget _connChip(AppState state, ThemeData theme) {
    if (state.isPcMode) {
      final ok = state.serverInfo?.running == true;
      return Container(
        margin: const EdgeInsets.only(right: 8),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: ok ? const Color(0xFF0E2A1A) : const Color(0xFF2A1A1A),
          borderRadius: BorderRadius.circular(20),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              ok ? Icons.wifi : Icons.wifi_off,
              size: 14,
              color: ok ? const Color(0xFF4ADE80) : const Color(0xFFF87171),
            ),
            const SizedBox(width: 4),
            Text(
              ok ? 'PC 服务 :${state.pcPort}' : '服务未启动',
              style: TextStyle(
                fontSize: 12,
                color: ok ? const Color(0xFF4ADE80) : const Color(0xFFF87171),
              ),
            ),
          ],
        ),
      );
    }
    final ok = state.remote?.isConfigured == true;
    return Container(
      margin: const EdgeInsets.only(right: 8),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: ok ? const Color(0xFF0E2A1A) : const Color(0xFF2A3350),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        ok ? state.remote!.host : '未连接',
        style: TextStyle(
          fontSize: 12,
          color: ok ? const Color(0xFF4ADE80) : const Color(0xFF7A86A0),
        ),
      ),
    );
  }

  Widget _body(AppState state, ThemeData theme) {
    return RefreshIndicator(
      onRefresh: () => state.refreshTasks(),
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        children: [
          if (state.isPcMode && state.serverInfo?.running == true)
            _serverBanner(state, theme),
          DropZone(
            onFile: _onFile,
            isPcMode: state.isPcMode,
            busy: _busy,
          ),
          const SizedBox(height: 20),
          _mifareEntry(theme),
          const SizedBox(height: 20),
          _sectionTitle(theme, state.tasks),
          const SizedBox(height: 4),
          if (state.tasks.isEmpty)
            _emptyState(theme)
          else
            ...state.tasks.map((t) => TaskCard(
                  task: t,
                  onTap: () => Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => ResultScreen(task: t),
                    ),
                  ),
                  onCancel: t.status.isRunning
                      ? () => state.cancelTask(t.id)
                      : null,
                  onBruteForce: (t.status == TaskStatus.failed &&
                          t.hashValue.isNotEmpty)
                      ? () => _startBruteForce(t)
                      : null,
                )),
        ],
      ),
    );
  }

  /// MIFARE 分析器入口。
  ///
  /// 放在这里而不是塞进设置里，是因为它是一个独立功能：不消耗 GPU、不依赖
  /// hashcat、也不需要连 PC，手机上单机就能用（卡片分析和 mfkey32 都是纯计算）。
  Widget _mifareEntry(ThemeData theme) {
    final accent = theme.colorScheme.primary;
    return InkWell(
      borderRadius: BorderRadius.circular(16),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => const MifareScreen()),
      ),
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: theme.cardTheme.color,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: accent.withOpacity(0.35), width: 1.5),
        ),
        child: Row(
          children: [
            Container(
              width: 46,
              height: 46,
              decoration: BoxDecoration(
                color: accent.withOpacity(0.12),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(Icons.nfc, color: accent, size: 24),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('MIFARE 卡片分析器', style: theme.textTheme.titleMedium),
                  const SizedBox(height: 3),
                  Text(
                    '解析门禁卡转储 · 生成密钥字典 · mfkey32 离线恢复密钥',
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: theme.textTheme.bodySmall?.color),
          ],
        ),
      ),
    );
  }

  Widget _serverBanner(AppState state, ThemeData theme) {
    final ip = state.serverInfo?.host ?? '';
    final port = state.serverInfo?.port ?? state.pcPort;
    final displayIp = (ip == '0.0.0.0' || ip.isEmpty) ? '局域网IP' : ip;
    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withOpacity(0.08),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: theme.colorScheme.primary.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Icon(Icons.phone_iphone, color: theme.colorScheme.primary, size: 22),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('手机连接地址', style: theme.textTheme.bodySmall),
                SelectableText(
                  '$displayIp:$port',
                  style: TextStyle(
                    fontWeight: FontWeight.w700,
                    fontSize: 16,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
              ],
            ),
          ),
          IconButton(
            icon: const Icon(Icons.copy, size: 18),
            onPressed: () {
              Clipboard.setData(ClipboardData(text: '$displayIp:$port'));
              _showSnack('已复制 $displayIp:$port');
            },
          ),
        ],
      ),
    );
  }

  Widget _sectionTitle(ThemeData theme, List<CrackTask> tasks) {
    return Row(
      children: [
        Text('任务列表', style: theme.textTheme.titleLarge),
        const SizedBox(width: 8),
        Text('${tasks.length}',
            style: TextStyle(
                color: theme.colorScheme.primary, fontWeight: FontWeight.w700)),
      ],
    );
  }

  Widget _emptyState(ThemeData theme) {
    return Container(
      margin: const EdgeInsets.only(top: 24),
      padding: const EdgeInsets.all(32),
      child: Column(
        children: [
          Icon(Icons.inbox_outlined,
              size: 56, color: theme.textTheme.bodySmall?.color),
          const SizedBox(height: 12),
          Text('还没有任务', style: theme.textTheme.titleMedium),
          const SizedBox(height: 4),
          Text('拖入文件开始自动破解', style: theme.textTheme.bodySmall),
        ],
      ),
    );
  }
}
