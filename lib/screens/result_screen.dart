import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:provider/provider.dart';
import '../models/task.dart';
import '../models/file_signatures.dart';
import '../state/app_state.dart';
import '../widgets/brute_force_sheet.dart';
import '../widgets/progress_view.dart';
import '../widgets/task_card.dart';

class ResultScreen extends StatelessWidget {
  final CrackTask task;

  const ResultScreen({super.key, required this.task});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final latest = state.tasks.firstWhere(
      (t) => t.id == task.id,
      orElse: () => task,
    );
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;

    return Scaffold(
      appBar: AppBar(
        title: Text(latest.fileName, maxLines: 1, overflow: TextOverflow.ellipsis),
        actions: [
          if (latest.status.isRunning)
            IconButton(
              icon: const Icon(Icons.stop_circle_outlined),
              onPressed: () => state.cancelTask(latest.id),
            ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _summary(latest, theme, accent),
          const SizedBox(height: 16),
          if (latest.status.isRunning) _runningBlock(latest, theme),
          if (latest.status == TaskStatus.cracked)
            _crackedBlock(latest, theme, accent),
          if (latest.status == TaskStatus.failed)
            _failedBlock(context, latest, theme),
          const SizedBox(height: 16),
          _hashBlock(latest, theme),
          const SizedBox(height: 16),
          _logBlock(latest, theme),
        ],
      ),
    );
  }

  Widget _summary(CrackTask t, ThemeData theme, Color accent) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: accent.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(11),
                  ),
                  child: Icon(iconForFileType(t.fileType),
                      size: 24, color: accent),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(t.fileName, style: theme.textTheme.titleMedium),
                      Text(t.fileType.label,
                          style: theme.textTheme.bodySmall),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            _kv('状态', t.status.label, theme),
            _kv('哈希模式', t.hashType > 0 ? '-m ${t.hashType}' : '--', theme),
            _kv('提取工具', t.fileType.extractorTool, theme),
            _kv('开始时间', _fmtTime(t.createdAt), theme),
            if (t.finishedAt != null)
              _kv('结束时间', _fmtTime(t.finishedAt!), theme),
            if (t.status.isRunning)
              _kv(
                  '当前阶段',
                  t.phaseDetail.isNotEmpty ? t.phaseDetail : t.currentPhase.label,
                  theme),
          ],
        ),
      ),
    );
  }

  Widget _runningBlock(CrackTask t, ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('破解进度', style: theme.textTheme.titleMedium),
            const SizedBox(height: 14),
            ProgressView(
              progress: t.progress,
              speedKhs: t.speedKhs,
              etaSeconds: t.etaSeconds,
              testedCount: t.testedCount,
              totalCount: t.totalCount,
              statusName: t.phaseDetail.isNotEmpty
                  ? t.phaseDetail
                  : t.currentPhase.label,
            ),
          ],
        ),
      ),
    );
  }

  Widget _crackedBlock(CrackTask t, ThemeData theme, Color accent) {
    return Card(
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: const Color(0xFF2E7D32).withOpacity(0.4)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.lock_open, color: Color(0xFF4ADE80)),
                const SizedBox(width: 8),
                Text('破解成功', style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0xFF0E2A1A),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: SelectableText(
                      t.plainPassword.isEmpty ? '(空密码)' : t.plainPassword,
                      style: const TextStyle(
                        color: Color(0xFF4ADE80),
                        fontSize: 24,
                        fontWeight: FontWeight.w700,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                  if (t.plainPassword.isNotEmpty)
                    IconButton(
                      icon: const Icon(Icons.copy),
                      color: const Color(0xFF4ADE80),
                      onPressed: () {
                        Clipboard.setData(
                            ClipboardData(text: t.plainPassword));
                      },
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _failedBlock(
      BuildContext context, CrackTask t, ThemeData theme) {
    final hasHash = t.hashValue.isNotEmpty;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.error_outline, color: Color(0xFFF87171)),
                const SizedBox(width: 8),
                Text('破解失败', style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              t.errorMessage.isEmpty ? '未能破解（所有策略已耗尽）' : t.errorMessage,
              style: TextStyle(color: const Color(0xFFF87171), fontSize: 13),
            ),
            if (hasHash) ...[
              const SizedBox(height: 14),
              Divider(color: theme.dividerColor.withOpacity(0.4), height: 1),
              const SizedBox(height: 14),
              Text(
                '换一条路：按字符集和长度直接穷举。'
                '开始前会先算好组合空间与预计耗时，跑起来后随时可以取消。',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  icon: const Icon(Icons.bolt, size: 20),
                  label: const Text('暴力破解'),
                  onPressed: () => _startBruteForce(context, t),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _startBruteForce(BuildContext context, CrackTask t) async {
    final state = context.read<AppState>();
    if (!state.isPcMode && (state.remote == null || !state.remote!.isConfigured)) {
      ScaffoldMessenger.of(context)
        ..clearSnackBars()
        ..showSnackBar(const SnackBar(
          content: Text('请先在设置里配置 PC 地址'),
          behavior: SnackBarBehavior.floating,
        ));
      return;
    }
    final cfg = await showBruteForceSheet(context, task: t);
    if (cfg == null) return;
    try {
      await state.retryWithBruteForce(t.id, cfg);
    } catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context)
        ..clearSnackBars()
        ..showSnackBar(SnackBar(
          content: Text('发起失败: $e'),
          behavior: SnackBarBehavior.floating,
        ));
    }
  }

  Widget _hashBlock(CrackTask t, ThemeData theme) {
    if (t.hashValue.isEmpty) return const SizedBox.shrink();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.fingerprint, size: 18),
                const SizedBox(width: 6),
                Text('哈希值', style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: theme.scaffoldBackgroundColor,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                t.hashValue,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _logBlock(CrackTask t, ThemeData theme) {
    if (t.log.trim().isEmpty) return const SizedBox.shrink();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.terminal, size: 18),
                const SizedBox(width: 6),
                Text('运行日志', style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              constraints: const BoxConstraints(maxHeight: 400),
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFF0A0F1E),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Scrollbar(
                child: SingleChildScrollView(
                  scrollDirection: Axis.vertical,
                  reverse: true,
                  child: SelectableText(
                    t.log,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                      color: Color(0xFF9FE7B0),
                      height: 1.4,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _kv(String k, String v, ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(
            width: 80,
            child: Text(k, style: theme.textTheme.bodySmall),
          ),
          Expanded(child: Text(v, style: theme.textTheme.bodyMedium)),
        ],
      ),
    );
  }

  String _fmtTime(DateTime t) {
    String two(int n) => n.toString().padLeft(2, '0');
    return '${t.year}-${two(t.month)}-${two(t.day)} '
        '${two(t.hour)}:${two(t.minute)}:${two(t.second)}';
  }
}
