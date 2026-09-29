import 'package:flutter/material.dart';

class ProgressView extends StatelessWidget {
  final double progress;
  final int speedKhs;
  final int etaSeconds;
  final int testedCount;
  final int totalCount;
  final String statusName;

  const ProgressView({
    super.key,
    this.progress = 0,
    this.speedKhs = 0,
    this.etaSeconds = 0,
    this.testedCount = 0,
    this.totalCount = 0,
    this.statusName = '',
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;
    final muted = theme.textTheme.bodySmall?.color;
    final fg = theme.colorScheme.onSurface;
    final pct = (progress * 100).clamp(0, 100);

    Widget stat(String value, String label) => Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(value,
                  style: TextStyle(
                      fontWeight: FontWeight.w700, fontSize: 15, color: fg)),
              Text(label, style: TextStyle(fontSize: 11, color: muted)),
            ],
          ),
        );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ClipRRect(
          borderRadius: BorderRadius.circular(8),
          child: LinearProgressIndicator(
            value: progress.clamp(0.0, 1.0),
            minHeight: 10,
            backgroundColor: accent.withOpacity(0.12),
            valueColor: AlwaysStoppedAnimation(accent),
          ),
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            stat('${pct.toStringAsFixed(1)}%', '进度'),
            stat(_speedLabel, '速度'),
            stat(_etaLabel, '预计'),
            if (statusName.isNotEmpty) stat(statusName, '状态'),
          ],
        ),
        if (totalCount > 0)
          Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text(
              '${_fmt(testedCount)} / ${_fmt(totalCount)}',
              style: TextStyle(fontSize: 12, color: muted),
            ),
          ),
      ],
    );
  }

  String get _speedLabel {
    if (speedKhs <= 0) return '--';
    if (speedKhs >= 1000) {
      return '${(speedKhs / 1000).toStringAsFixed(2)} M/s';
    }
    return '$speedKhs k/s';
  }

  String get _etaLabel {
    if (etaSeconds <= 0) return '--';
    if (etaSeconds > 86400) return '${(etaSeconds / 86400).ceil()} 天';
    if (etaSeconds > 3600) return '${(etaSeconds / 3600).ceil()} 时';
    if (etaSeconds > 60) return '${(etaSeconds / 60).ceil()} 分';
    return '$etaSeconds 秒';
  }

  String _fmt(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(2)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}k';
    return '$n';
  }
}
