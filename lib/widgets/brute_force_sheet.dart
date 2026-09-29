import 'package:flutter/material.dart';
import '../models/brute_force.dart';
import '../models/task.dart';

/// 弹出「暴力破解」配置面板。
///
/// 返回用户确认的配置；用户取消则返回 null。
///
/// 设计要点：**先算账，再动手**。
/// 暴力破解的代价区间极大（几秒 ~ 一万年），如果只是给一个「开始」按钮，
/// 用户点了之后要么以为软件坏了，要么把电脑押上去一天。所以面板必须
/// 实时显示「组合空间」和「预计耗时」，并把耗时按量级染色告警。
Future<BruteForceConfig?> showBruteForceSheet(
  BuildContext context, {
  required CrackTask task,
}) {
  return showModalBottomSheet<BruteForceConfig>(
    context: context,
    isScrollControlled: true,
    backgroundColor: Theme.of(context).colorScheme.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
    ),
    builder: (_) => BruteForceSheet(task: task),
  );
}

class BruteForceSheet extends StatefulWidget {
  final CrackTask task;
  const BruteForceSheet({super.key, required this.task});

  @override
  State<BruteForceSheet> createState() => _BruteForceSheetState();
}

class _BruteForceSheetState extends State<BruteForceSheet> {
  late List<BruteForceConfig> _presets;
  late BruteForceConfig _cfg;

  /// 固定前缀输入框。用 controller 是为了在切换预设时能同步清空。
  late final TextEditingController _prefixCtl;

  /// 当前选中的预设下标；-1 表示用户已手动改过参数（自定义）。
  int _presetIndex = 0;

  /// 运行方式：0 = 不限时，其余为限时秒数。
  int _runtimeSec = 0;

  /// 实测速度（次/秒）。取任务上记录的最近一次实测值。
  int get _speedPerSec => widget.task.speedKhs * 1000;

  @override
  void initState() {
    super.initState();
    _presets = recommendedBruteForcePresets(widget.task.hashType);
    _cfg = _presets.first;
    _prefixCtl = TextEditingController(text: _cfg.prefix);
  }

  @override
  void dispose() {
    _prefixCtl.dispose();
    super.dispose();
  }

  void _applyPreset(int index) {
    setState(() {
      _presetIndex = index;
      _cfg = _presets[index];
      // 预设不带前缀，输入框也要跟着清掉，否则界面与配置不一致
      if (_prefixCtl.text != _cfg.prefix) _prefixCtl.text = _cfg.prefix;
    });
  }

  void _applyCustom(CharsetPreset? charset, int? minLen, int? maxLen,
      {String? prefix}) {
    setState(() {
      _presetIndex = -1;
      _cfg = BruteForceConfig.normalized(
        charset: charset ?? _cfg.charset,
        minLen: minLen ?? _cfg.minLen,
        maxLen: maxLen ?? _cfg.maxLen,
        prefix: prefix ?? _cfg.prefix,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;
    final speed = _speedPerSec;
    final ks = _cfg.keyspace;
    // 用 BigInt 秒而不是 Duration：超大空间下 Duration 会溢出成负数，
    // 把「几百万年」显示成「不到 1 秒」。详见 BruteForceConfig.etaSeconds。
    final etaSecs = speed > 0 ? _cfg.etaSeconds(speed) : null;

    return SafeArea(
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxHeight: MediaQuery.of(context).size.height * 0.88,
        ),
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 12, 20, 20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Center(
                child: Container(
                  width: 40,
                  height: 4,
                  margin: const EdgeInsets.only(bottom: 14),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.onSurface.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              Row(
                children: [
                  Icon(Icons.bolt, color: accent, size: 22),
                  const SizedBox(width: 8),
                  Text('暴力破解', style: theme.textTheme.titleLarge),
                  const Spacer(),
                  Text('-m ${widget.task.hashType}',
                      style: theme.textTheme.bodySmall),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                '按字符集逐位穷举。已知口令的「固定开头」时填进前缀，'
                '空间会按真实规模计算（如 z + 9 位数字 = 10 亿，'
                '而不是把 z 也当可变位去乘 26 倍）。',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 16),

              _sectionLabel(theme, '推荐方案'),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (var i = 0; i < _presets.length; i++)
                    ChoiceChip(
                      label: Text(_presets[i].label,
                          style: const TextStyle(fontSize: 12)),
                      selected: _presetIndex == i,
                      onSelected: (_) => _applyPreset(i),
                    ),
                  ChoiceChip(
                    label: const Text('自定义', style: TextStyle(fontSize: 12)),
                    selected: _presetIndex == -1,
                    onSelected: (_) => _applyCustom(null, null, null),
                  ),
                ],
              ),
              const SizedBox(height: 18),

              _sectionLabel(theme, '字符集'),
              const SizedBox(height: 8),
              _charsetSelector(theme, accent),
              const SizedBox(height: 18),

              _sectionLabel(theme, '长度范围'),
              const SizedBox(height: 8),
              _lengthSelector(theme, accent),
              const SizedBox(height: 18),

              _sectionLabel(theme, '固定前缀（可选）'),
              const SizedBox(height: 8),
              _prefixField(theme),
              const SizedBox(height: 18),

              _sectionLabel(theme, '运行方式'),
              const SizedBox(height: 8),
              _runtimeSelector(theme),
              const SizedBox(height: 18),

              _estimateCard(theme, ks, etaSecs, speed),
              const SizedBox(height: 12),
              _breakdown(theme, speed),
              const SizedBox(height: 18),

              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => Navigator.pop(context),
                      style: OutlinedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                      child: const Text('取消'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: FilledButton.icon(
                      onPressed: () => Navigator.pop(
                          context,
                          _cfg.copyWith(
                            runtimeSec: _runtimeSec,
                            // 以输入框的当前内容为准，避免用户输了却忘了触发 onChanged
                            prefix: _prefixCtl.text,
                          )),
                      icon: const Icon(Icons.play_arrow, size: 20),
                      label: const Text('开始破解'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _sectionLabel(ThemeData theme, String text) =>
      Text(text, style: theme.textTheme.titleMedium);

  /// 固定前缀输入框。
  ///
  /// 这是把「字母开头 + N 位数字」这类口令从 26 倍代价降到真实代价的关键：
  /// 不填前缀时行为与以前完全一致（掩码 = 纯字符集位）。
  Widget _prefixField(ThemeData theme) {
    return TextField(
      controller: _prefixCtl,
      maxLength: 32,
      autocorrect: false,
      enableSuggestions: false,
      decoration: InputDecoration(
        hintText: '例如 z（口令以 z 开头则只穷举后面的部分）',
        counterText: '',
        isDense: true,
        prefixIcon: const Icon(Icons.flag_outlined, size: 18),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
        ),
      ),
      style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
      onChanged: (v) => _applyCustom(null, null, null, prefix: v),
    );
  }

  Widget _charsetSelector(ThemeData theme, Color accent) {
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        for (final c in CharsetPreset.values)
          ChoiceChip(
            label: Text('${c.label}（${c.sample}）',
                style: const TextStyle(fontSize: 12)),
            selected: _cfg.charset == c,
            onSelected: (_) => _applyCustom(c, null, null),
          ),
      ],
    );
  }

  Widget _lengthSelector(ThemeData theme, Color accent) {
    return Row(
      children: [
        Expanded(
          child: _numField(
            theme,
            label: '最短',
            value: _cfg.minLen,
            // 最短不能超过最长，否则区间为空；直接把上限夹住，
            // 比事后弹一个报错更顺手。
            max: _cfg.maxLen,
            onChanged: (v) => _applyCustom(null, v, null),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _numField(
            theme,
            label: '最长',
            value: _cfg.maxLen,
            max: 16,
            onChanged: (v) => _applyCustom(null, null, v),
          ),
        ),
      ],
    );
  }

  Widget _numField(ThemeData theme,
      {required String label,
      required int value,
      required int max,
      required void Function(int) onChanged}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: theme.inputDecorationTheme.fillColor,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Text(label, style: theme.textTheme.bodySmall),
          const Spacer(),
          IconButton(
            visualDensity: VisualDensity.compact,
            iconSize: 18,
            icon: const Icon(Icons.remove),
            onPressed: value <= 1 ? null : () => onChanged(value - 1),
          ),
          SizedBox(
            width: 26,
            child: Text('$value',
                textAlign: TextAlign.center,
                style: const TextStyle(
                    fontWeight: FontWeight.w700, fontSize: 16)),
          ),
          IconButton(
            visualDensity: VisualDensity.compact,
            iconSize: 18,
            icon: const Icon(Icons.add),
            onPressed: value >= max ? null : () => onChanged(value + 1),
          ),
        ],
      ),
    );
  }

  Widget _runtimeSelector(ThemeData theme) {
    const options = <int, String>{
      0: '不限时',
      600: '10 分钟',
      3600: '1 小时',
      21600: '6 小时',
    };
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        for (final e in options.entries)
          ChoiceChip(
            label: Text(e.value, style: const TextStyle(fontSize: 12)),
            selected: _runtimeSec == e.key,
            onSelected: (_) => setState(() => _runtimeSec = e.key),
          ),
      ],
    );
  }

  /// 组合空间 + 预计耗时。这是整个面板存在的理由。
  Widget _estimateCard(
      ThemeData theme, BigInt ks, BigInt? etaSecs, int speed) {
    final color = _etaColor(etaSecs, speed);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withOpacity(0.5)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: _metric(
                    theme, '组合空间', formatKeyspace(ks), color),
              ),
              Expanded(
                child: _metric(
                  theme,
                  '预计耗时',
                  etaSecs == null ? '—' : formatSeconds(etaSecs),
                  color,
                ),
              ),
            ],
          ),
          if (speed > 0) ...[
            const SizedBox(height: 8),
            Text('按实测速度 ${_speedLabel(speed)} 估算',
                style: theme.textTheme.bodySmall),
          ] else ...[
            const SizedBox(height: 8),
            Text('本机还没有实测速度（先跑一次字典或掩码攻击即可获得）',
                style: theme.textTheme.bodySmall),
          ],
          const SizedBox(height: 8),
          Text(_etaHint(etaSecs, speed),
              style: TextStyle(color: color, fontSize: 12, height: 1.4)),
        ],
      ),
    );
  }

  Widget _metric(ThemeData theme, String label, String value, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: theme.textTheme.bodySmall),
        const SizedBox(height: 2),
        Text(value,
            style: TextStyle(
                color: color, fontSize: 18, fontWeight: FontWeight.w700)),
      ],
    );
  }

  /// 逐长度列出组合空间，方便用户判断「到底从几位开始试值得」。
  /// 长度超过 6 档时只显示头尾，避免面板被撑爆。
  Widget _breakdown(ThemeData theme, int speed) {
    if (_cfg.minLen > _cfg.maxLen) return const SizedBox.shrink();
    final rows = <Widget>[];
    for (var len = _cfg.minLen; len <= _cfg.maxLen; len++) {
      final one = BruteForceConfig(
          charset: _cfg.charset, minLen: len, maxLen: len);
      final ks = one.keyspace;
      final etaSecs = speed > 0 ? one.etaSeconds(speed) : null;
      rows.add(Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          children: [
            SizedBox(
              width: 64,
              child: Text('$len 位',
                  style: theme.textTheme.bodySmall),
            ),
            Expanded(
              child: Text(formatKeyspace(ks),
                  style: const TextStyle(fontSize: 12)),
            ),
            Text(etaSecs == null ? '' : formatSeconds(etaSecs),
                style: theme.textTheme.bodySmall),
          ],
        ),
      ));
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('各长度明细', style: theme.textTheme.bodySmall),
        const SizedBox(height: 4),
        ...rows,
      ],
    );
  }

  Color _etaColor(BigInt? etaSecs, int speed) {
    if (speed <= 0 || etaSecs == null) return const Color(0xFF7A86A0);
    if (etaSecs >= BigInt.from(86400)) return const Color(0xFFF87171);
    if (etaSecs >= BigInt.from(3600)) return const Color(0xFFFBBF24);
    return const Color(0xFF4ADE80);
  }

  String _etaHint(BigInt? etaSecs, int speed) {
    if (speed <= 0) {
      return '提示：先跑一次自动策略拿到实测速度，这里才能给出可信的耗时。';
    }
    if (etaSecs == null) return '';
    if (etaSecs >= BigInt.from(86400)) {
      return '⚠ 这个空间太大（超过一天）。建议先缩小长度或字符集，'
          '或者先补一个更贴近目标习惯的字典。';
    }
    if (etaSecs >= BigInt.from(3600)) {
      return '空间较大，需要跑上一阵子。可以选「不限时」，'
          '让它自己在后台跑，随时可以取消。';
    }
    return '空间不大，很快就能跑完。';
  }

  String _speedLabel(int speed) {
    if (speed >= 1000000) return '${(speed / 1000000).toStringAsFixed(1)} M/s';
    if (speed >= 1000) return '${(speed / 1000).toStringAsFixed(1)} k/s';
    return '$speed /s';
  }
}
