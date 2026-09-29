import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/task.dart';
import '../models/file_type.dart';
import '../models/file_signatures.dart';
import 'progress_view.dart';

/// 图标名 → Material 图标。
///
/// 用「名字 → 图标」的映射而不是对枚举做 switch：类型已经扩到 40 多种，
/// 每加一种都要改 switch 太脆；漏掉时这里会回退到通用图标而不是编译不过。
const Map<String, IconData> _iconByName = {
  'archive_lock': Icons.folder_zip_outlined,
  'pdf': Icons.picture_as_pdf_outlined,
  'document_locked': Icons.description_outlined,
  'wifi': Icons.wifi_lock_outlined,
  'shield_key': Icons.key_outlined,
  'hdd': Icons.storage_outlined,
  'disc': Icons.album_outlined,
  'wallet': Icons.account_balance_wallet_outlined,
  'browser': Icons.travel_explore_outlined,
  'windows': Icons.desktop_windows_outlined,
  'phone': Icons.phone_android_outlined,
  'java': Icons.coffee_outlined,
  'fingerprint': Icons.fingerprint,
  'nfc': Icons.nfc,
  'vpn_key': Icons.vpn_key_outlined,
  'help': Icons.help_outline,
};

IconData iconForFileType(DetectedFileType t) =>
    _iconByName[t.iconName] ?? Icons.insert_drive_file_outlined;

class TaskCard extends StatelessWidget {
  final CrackTask task;
  final VoidCallback? onTap;
  final VoidCallback? onCancel;

  /// 失败任务上「暴力破解」按钮的回调。为 null 时不显示该按钮。
  final VoidCallback? onBruteForce;
  final bool showActions;

  const TaskCard({
    super.key,
    required this.task,
    this.onTap,
    this.onCancel,
    this.onBruteForce,
    this.showActions = true,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;

    return Card(
      margin: const EdgeInsets.symmetric(vertical: 6),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _header(theme, accent),
              const SizedBox(height: 12),
              if (task.status.isRunning)
                ProgressView(
                  progress: task.progress,
                  speedKhs: task.speedKhs,
                  etaSeconds: task.etaSeconds,
                  testedCount: task.testedCount,
                  totalCount: task.totalCount,
                  statusName: task.currentPhase == TaskPhaseType.none
                      ? task.status.label
                      : (task.phaseDetail.isNotEmpty
                          ? task.phaseDetail
                          : task.currentPhase.label),
                )
              else if (task.status == TaskStatus.cracked)
                _crackedResult(theme, accent)
              else if (task.status == TaskStatus.failed)
                _failedInfo(theme)
              else
                _pendingInfo(theme),
              if (task.hashValue.isNotEmpty) _hashLine(theme),
              if (showActions) _actions(theme, accent),
            ],
          ),
        ),
      ),
    );
  }

  Widget _header(ThemeData theme, Color accent) {
    return Row(
      children: [
        Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            color: accent.withOpacity(0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(iconForFileType(task.fileType),
              size: 22, color: accent),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(task.fileName,
                  style: theme.textTheme.titleMedium,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis),
              Text(
                task.fileType == DetectedFileType.unknown
                    ? task.status.label
                    : '${task.fileType.label} · -m ${task.hashType}',
                style: theme.textTheme.bodySmall,
              ),
            ],
          ),
        ),
        _statusBadge(theme),
      ],
    );
  }

  Widget _statusBadge(ThemeData theme) {
    Color bg;
    Color fg;
    switch (task.status) {
      case TaskStatus.cracked:
        bg = const Color(0xFF1B4D2E);
        fg = const Color(0xFF4ADE80);
        break;
      case TaskStatus.failed:
      case TaskStatus.cancelled:
        bg = const Color(0xFF3D1A1A);
        fg = const Color(0xFFF87171);
        break;
      case TaskStatus.cracking:
      case TaskStatus.identifying:
      case TaskStatus.extracting:
        bg = accentBg(theme);
        fg = theme.colorScheme.primary;
        break;
      case TaskStatus.pending:
        bg = const Color(0xFF2A3350);
        fg = const Color(0xFF7A86A0);
        break;
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(task.status.label,
          style: TextStyle(
              color: fg, fontSize: 12, fontWeight: FontWeight.w600)),
    );
  }

  Color accentBg(ThemeData theme) => theme.colorScheme.primary.withOpacity(0.14);

  Widget _crackedResult(ThemeData theme, Color accent) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF0E2A1A),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF2E7D32).withOpacity(0.5)),
      ),
      child: Row(
        children: [
          const Icon(Icons.lock_open, color: Color(0xFF4ADE80), size: 22),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('密码', style: theme.textTheme.bodySmall),
                SelectableText(
                  task.plainPassword.isEmpty ? '(空)' : task.plainPassword,
                  style: const TextStyle(
                    color: Color(0xFF4ADE80),
                    fontSize: 20,
                    fontWeight: FontWeight.w700,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
          if (task.plainPassword.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.copy, size: 20),
              color: const Color(0xFF4ADE80),
              tooltip: '复制',
              onPressed: () {
                Clipboard.setData(ClipboardData(text: task.plainPassword));
              },
            ),
        ],
      ),
    );
  }

  Widget _failedInfo(ThemeData theme) {
    // 所有自动策略都没命中时，暴力破解是最后一条路。
    // 入口直接摆在失败提示里，不让用户去翻菜单找。
    final showBruteForce = onBruteForce != null && task.hashValue.isNotEmpty;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF2A1A1A),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.error_outline,
                  color: Color(0xFFF87171), size: 20),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  task.errorMessage.isEmpty ? '未能破解' : task.errorMessage,
                  style: TextStyle(
                      color: const Color(0xFFF87171), fontSize: 13),
                ),
              ),
            ],
          ),
          if (showBruteForce) ...[
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                icon: const Icon(Icons.bolt, size: 18),
                label: const Text('暴力破解'),
                style: FilledButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 10),
                  textStyle: const TextStyle(
                      fontSize: 13, fontWeight: FontWeight.w600),
                ),
                onPressed: onBruteForce,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _pendingInfo(ThemeData theme) {
    return Text('排队等待中…', style: theme.textTheme.bodySmall);
  }

  Widget _hashLine(ThemeData theme) {
    final muted = theme.textTheme.bodySmall?.color;
    return Padding(
      padding: const EdgeInsets.only(top: 10),
      child: Row(
        children: [
          Icon(Icons.fingerprint, size: 14, color: muted),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              task.hashValue.length > 60
                  ? '${task.hashValue.substring(0, 60)}…'
                  : task.hashValue,
              style: TextStyle(
                  fontFamily: 'monospace', fontSize: 11, color: muted),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _actions(ThemeData theme, Color accent) {
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          if (task.status.isRunning && onCancel != null)
            TextButton.icon(
              onPressed: onCancel,
              icon: const Icon(Icons.stop_circle_outlined, size: 18),
              label: const Text('取消'),
              style: TextButton.styleFrom(foregroundColor: Colors.redAccent),
            ),
          if (onTap != null)
            TextButton.icon(
              onPressed: onTap,
              icon: Icon(Icons.terminal, size: 18, color: accent),
              label: const Text('详情'),
            ),
        ],
      ),
    );
  }
}
