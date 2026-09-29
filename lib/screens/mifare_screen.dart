// MIFARE 卡片分析器界面。
//
// 分成两件事做，因为它们各自的输入和输出完全不同：
//
//   1) 转储分析：读一张卡片转储，把它「讲明白」——UID/ATQA/SAK 是什么卡、
//      每个扇区的 Key A / Key B / 访问位是什么、哪些钥匙已知哪些未知、
//      数据还读不读得出来；然后生成一份可以直接喂给 Proxmark/Flipper 的
//      密钥字典，以及下一步该敲什么命令。
//
//   2) 密钥恢复：用 mfkey32 的 nonce 日志离线反推密钥。这是**唯一**一条
//      只靠文件就能算出未知密钥的路——因为 nonce 里带着密文，有校验靶子。

import 'dart:io';

import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:provider/provider.dart';

import '../models/mifare.dart';
import '../models/mifare_keys.dart';
import '../services/mifare_service.dart';
import '../state/app_state.dart';

/// 等宽字体兜底链：Windows 上 Consolas，macOS 上 Menlo，安卓上 monospace。
const List<String> _monoFallback = [
  'Consolas',
  'Cascadia Mono',
  'Menlo',
  'DejaVu Sans Mono',
  'monospace',
];

class MifareScreen extends StatefulWidget {
  /// 从主界面拖入文件时带过来的路径，可空（手动打开分析器的情况）
  final String? initialPath;

  const MifareScreen({super.key, this.initialPath});

  @override
  State<MifareScreen> createState() => _MifareScreenState();
}

class _MifareScreenState extends State<MifareScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;

  // ---- 转储分析状态 ----
  bool _analyzing = false;
  String? _dumpPath;
  MifareAnalysisResult? _analysis;
  String? _analysisError;

  // ---- 密钥恢复状态 ----
  bool _recovering = false;
  String? _noncePath;
  MifareRecoveryResult? _recovery;
  String? _recoveryError;

  bool _hovering = false;
  bool _exporting = false;

  @override
  void initState() {
    super.initState();
    final initial = widget.initialPath;
    // 拖进来的如果是 nonce 日志，直接落到第二个标签页，省一次点击
    final isNonce = initial != null &&
        initial.toLowerCase().contains('mfkey32');
    _tabs = TabController(length: 2, vsync: this, initialIndex: isNonce ? 1 : 0);
    if (initial != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        if (isNonce) {
          _recoverFrom(initial);
        } else {
          _analyze(initial);
        }
      });
    }
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  MifareService get _service => context.read<AppState>().mifareService;

  void _snack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(
        content: Text(msg),
        behavior: SnackBarBehavior.floating,
      ));
  }

  // ------------------------------------------------------------ 转储分析

  Future<void> _analyze(String path) async {
    setState(() {
      _analyzing = true;
      _analysisError = null;
      _dumpPath = path;
      _analysis = null;
    });
    try {
      final result = await _service.analyze(path);
      if (!mounted) return;
      setState(() => _analysis = result);
    } catch (e) {
      if (!mounted) return;
      setState(() => _analysisError = '$e');
    } finally {
      if (mounted) setState(() => _analyzing = false);
    }
  }

  Future<void> _pickDump() async {
    final files = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['nfc', 'shd', 'eml', 'mfd', 'bin', 'dump'],
    );
    if (files.isEmpty) return;
    final p = files.first.path;
    if (p != null && p.isNotEmpty) await _analyze(p);
  }

  /// 导出密钥字典。
  ///
  /// 桌面端先让用户挑目录（方便直接丢进 Proxmark 的目录），取消则退回转储
  /// 所在目录；移动端没法弹目录选择器，就直接写在转储旁边。
  Future<void> _export() async {
    final analysis = _analysis;
    final dumpPath = _dumpPath;
    if (analysis == null || dumpPath == null) return;

    final state = context.read<AppState>();
    String? dir;
    if (state.isPcMode) {
      dir = await FilePicker.getDirectoryPath(
        dialogTitle: '选择密钥字典的导出目录',
      );
      if (dir == null) return; // 用户取消
    }
    if (dir == null || dir.isEmpty) {
      dir = File(dumpPath).parent.path;
    }

    final base = File(dumpPath).uri.pathSegments.last
        .replaceAll(RegExp(r'\.[^.]+$'), '');

    setState(() => _exporting = true);
    try {
      final paths = await _service.exportKeys(dir, analysis, base);
      _snack('已导出 ${paths.length} 个文件到 $dir');
    } catch (e) {
      _snack('导出失败：$e');
    } finally {
      if (mounted) setState(() => _exporting = false);
    }
  }

  // ------------------------------------------------------------ 密钥恢复

  Future<void> _recoverFrom(String path) async {
    setState(() {
      _recovering = true;
      _recoveryError = null;
      _noncePath = path;
      _recovery = null;
    });
    try {
      final result = await _service.recoverFromNonceLog(path);
      if (!mounted) return;
      setState(() => _recovery = result);
    } catch (e) {
      if (!mounted) return;
      setState(() => _recoveryError = '$e');
    } finally {
      if (mounted) setState(() => _recovering = false);
    }
  }

  Future<void> _pickNonceLog() async {
    final files = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['log', 'txt'],
    );
    if (files.isEmpty) return;
    final p = files.first.path;
    if (p != null && p.isNotEmpty) await _recoverFrom(p);
  }

  // ------------------------------------------------------------ 构建

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('MIFARE 卡片分析器'),
        bottom: TabBar(
          controller: _tabs,
          indicatorColor: theme.colorScheme.primary,
          labelColor: theme.colorScheme.primary,
          tabs: const [
            Tab(text: '转储分析', icon: Icon(Icons.nfc, size: 20)),
            Tab(text: '密钥恢复', icon: Icon(Icons.vpn_key, size: 20)),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabs,
        children: [
          _dumpTab(theme),
          _recoverTab(theme),
        ],
      ),
    );
  }

  // ---------- 标签页 1：转储分析 ----------

  Widget _dumpTab(ThemeData theme) {
    final analysis = _analysis;

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
      children: [
        _pickCard(
          theme: theme,
          icon: Icons.nfc,
          title: '选择卡片转储文件',
          subtitle: '支持 Flipper .nfc/.shd、Proxmark/mfoc .eml、裸 .bin/.mfd',
          buttonLabel: _dumpPath == null ? '选择文件' : '换一个文件',
          busy: _analyzing,
          onPick: _pickDump,
          onDrop: _analyze,
        ),
        if (_dumpPath != null) ...[
          const SizedBox(height: 12),
          _pathLine(theme, _dumpPath!),
        ],
        if (_analysisError != null) ...[
          const SizedBox(height: 16),
          _errorBox(theme, _analysisError!),
        ],
        if (analysis != null) ...[
          const SizedBox(height: 18),
          _summaryCard(theme, analysis),
          const SizedBox(height: 14),
          _sectorTable(theme, analysis.dump),
          const SizedBox(height: 14),
          _candidatesCard(theme, analysis.candidates, analysis.dump),
          const SizedBox(height: 14),
          _textCard(
            theme: theme,
            icon: Icons.assignment_outlined,
            title: '诊断报告',
            body: analysis.report,
          ),
          const SizedBox(height: 14),
          _textCard(
            theme: theme,
            icon: Icons.alt_route,
            title: '下一步怎么做',
            body: analysis.advice,
          ),
          const SizedBox(height: 18),
          FilledButton.icon(
            onPressed: _exporting ? null : _export,
            icon: _exporting
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.save_alt),
            label: Text(_exporting ? '正在导出…' : '导出密钥字典与报告'),
          ),
        ],
      ],
    );
  }

  Widget _summaryCard(ThemeData theme, MifareAnalysisResult a) {
    final d = a.dump;
    final locked = d.lockedSectors;
    final unknown = d.unknownKeySlots;

    return _section(
      theme: theme,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.credit_card, size: 20, color: theme.colorScheme.primary),
              const SizedBox(width: 8),
              Expanded(
                child: Text(d.fileName, style: theme.textTheme.titleMedium),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _kv(theme, '载体格式', d.format.label),
          _kv(theme, '卡片类型', d.cardType),
          _kv(theme, 'UID', d.uidHex.isEmpty ? '未记录' : d.uidHex),
          _kv(theme, 'ATQA', d.atqaHex),
          _kv(theme, 'SAK', d.sakHex),
          _kv(theme, '扇区 / 块', '${d.sectors.length} 扇区 / ${d.blockCount} 块'),
          _kv(theme, '已知密钥', '${d.knownKeys.length} 把'),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _pill(
                theme,
                locked.isEmpty ? '全部扇区可读' : '${locked.length} 个扇区不可读',
                locked.isEmpty ? const Color(0xFF4ADE80) : const Color(0xFFF87171),
              ),
              if (unknown.isNotEmpty)
                _pill(theme, '${unknown.length} 处密钥未知',
                    const Color(0xFFFBBF24)),
            ],
          ),
          if (locked.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(
              '读不出来的是扇区：${locked.map((e) => '${e + 1}').join('、')}'
              '（卡片上是 1 起数，报告里是 0 起数）',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ],
      ),
    );
  }

  /// 逐扇区明细表。用横向滚动避免窄屏挤成一团。
  Widget _sectorTable(ThemeData theme, MifareDump dump) {
    final rows = dump.sectors.map((s) {
      final v = dump.verdictFor(s);
      return (
        index: s.index,
        keyA: _hexOrQuestion(s.keyA),
        keyB: _hexOrQuestion(s.keyB),
        access: s.accessBytes == null
            ? '?? ?? ??'
            : s.accessBytes!
                .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
                .join(' '),
        verdict: v,
      );
    }).toList();

    return _section(
      theme: theme,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('扇区明细', style: theme.textTheme.titleMedium),
          const SizedBox(height: 4),
          Text('Key A 在卡片设计上永远读不出来，dump 里的 ?? 属正常现象。',
              style: theme.textTheme.bodySmall),
          const SizedBox(height: 12),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              headingRowHeight: 36,
              dataRowMinHeight: 34,
              dataRowMaxHeight: 44,
              columnSpacing: 18,
              headingTextStyle: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                color: theme.colorScheme.primary,
              ),
              dataTextStyle: TextStyle(
                fontSize: 12,
                fontFamilyFallback: _monoFallback,
                color: theme.colorScheme.onSurface,
              ),
              columns: const [
                DataColumn(label: Text('扇区')),
                DataColumn(label: Text('Key A')),
                DataColumn(label: Text('Key B')),
                DataColumn(label: Text('访问位')),
                DataColumn(label: Text('状态')),
              ],
              rows: rows
                  .map((r) => DataRow(cells: [
                        DataCell(Text('${r.index + 1}')),
                        DataCell(Text(r.keyA)),
                        DataCell(Text(r.keyB)),
                        DataCell(Text(r.access)),
                        DataCell(_verdictChip(theme, r.verdict)),
                      ]))
                  .toList(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _verdictChip(ThemeData theme, MifareSectorVerdict v) {
    late final String text;
    late final Color color;
    if (v.dataReadable && !v.hasUnknownKey) {
      text = '可读';
      color = const Color(0xFF4ADE80);
    } else if (v.dataReadable) {
      text = '可读（密钥待补）';
      color = const Color(0xFFFBBF24);
    } else {
      text = '不可读';
      color = const Color(0xFFF87171);
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.4)),
      ),
      child: Text(text, style: TextStyle(fontSize: 11, color: color)),
    );
  }

  Widget _candidatesCard(
      ThemeData theme, List<MifareKeyCandidate> keys, MifareDump dump) {
    return _section(
      theme: theme,
      child: ExpansionTile(
        tilePadding: EdgeInsets.zero,
        childrenPadding: EdgeInsets.zero,
        shape: const Border(),
        collapsedShape: const Border(),
        title: Text('候选密钥表（${keys.length} 把）',
            style: theme.textTheme.titleMedium),
        subtitle: Text('转储已知 + 常见默认密钥，可直接当字典用',
            style: theme.textTheme.bodySmall),
        children: [
          for (final k in keys)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 5),
              child: Row(
                children: [
                  SelectableText(
                    k.key,
                    style: TextStyle(
                      fontFamilyFallback: _monoFallback,
                      fontSize: 13,
                      color: theme.colorScheme.primary,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      k.source,
                      style: theme.textTheme.bodySmall,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: () {
                Clipboard.setData(ClipboardData(
                    text: buildKeysFile(keys)));
                _snack('已复制密钥字典到剪贴板');
              },
              icon: const Icon(Icons.copy, size: 16),
              label: const Text('复制字典'),
            ),
          ),
        ],
      ),
    );
  }

  // ---------- 标签页 2：密钥恢复 ----------

  Widget _recoverTab(ThemeData theme) {
    final recovery = _recovery;

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
      children: [
        _section(
          theme: theme,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.info_outline,
                      size: 18, color: theme.colorScheme.primary),
                  const SizedBox(width: 8),
                  Text('这个功能靠什么成立', style: theme.textTheme.titleMedium),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                'MIFARE Classic 在认证时会交换密文。mfkey32 攻击用两次认证会话的'
                '随机数（nonce），把 48 位密钥的搜索空间从 2⁴⁸ 压到可枚举的规模，'
                '所以能纯离线算出来——这也是唯一一条只用文件就能恢复密钥的路。\n\n'
                '需要的是 Flipper 的 mfkey32.log（NFC → 已保存 → 选卡 → '
                '「检测读卡器」，贴着目标读卡器多认证几次后生成），'
                '或 mfkey_extract / Proxmark3 导出的同类文本。',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFFFBBF24).withOpacity(0.08),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                      color: const Color(0xFFFBBF24).withOpacity(0.3)),
                ),
                child: Text(
                  '请只用于你自己拥有或已获授权的卡片。',
                  style: TextStyle(
                      fontSize: 12, color: const Color(0xFFFBBF24)),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        _pickCard(
          theme: theme,
          icon: Icons.vpn_key,
          title: '选择 nonce 日志',
          subtitle: 'mfkey32.log / mfkey_extract 输出 / pm3 文本均可',
          buttonLabel: _noncePath == null ? '选择文件' : '换一个文件',
          busy: _recovering,
          onPick: _pickNonceLog,
          onDrop: _recoverFrom,
        ),
        if (_noncePath != null) ...[
          const SizedBox(height: 12),
          _pathLine(theme, _noncePath!),
        ],
        if (_recoveryError != null) ...[
          const SizedBox(height: 16),
          _errorBox(theme, _recoveryError!),
        ],
        if (recovery != null) ...[
          const SizedBox(height: 18),
          if (recovery.success)
            _keyResultCard(theme, recovery)
          else
            _section(
              theme: theme,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.sentiment_dissatisfied,
                          size: 20, color: Color(0xFFF87171)),
                      const SizedBox(width: 8),
                      Text('没能算出密钥', style: theme.textTheme.titleMedium),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '常见原因：\n'
                    '· 日志里的两组 nonce 不是同一次认证（同一张卡、同一个密钥才行）\n'
                    '· 采集时只认证了一次，凑不成一对\n'
                    '· 复制粘贴时漏了行或被工具改写过\n\n'
                    '建议重新采集：多刷几次再导出，本工具会自动两两配对尝试。',
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),
          const SizedBox(height: 14),
          _textCard(
            theme: theme,
            icon: Icons.terminal,
            title: '处理日志（耗时 ${recovery.elapsedMs} 毫秒）',
            body: [
              '解析到 ${recovery.records.length} 组 nonce 记录',
              ...recovery.log,
            ].join('\n'),
          ),
          if (recovery.records.isNotEmpty) ...[
            const SizedBox(height: 14),
            _nonceListCard(theme, recovery.records),
          ],
        ],
      ],
    );
  }

  Widget _keyResultCard(ThemeData theme, MifareRecoveryResult r) {
    return _section(
      theme: theme,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.check_circle, size: 22, color: Color(0xFF4ADE80)),
              const SizedBox(width: 8),
              Text('恢复成功', style: theme.textTheme.titleMedium),
              const Spacer(),
              Text('${r.elapsedMs} 毫秒', style: theme.textTheme.bodySmall),
            ],
          ),
          const SizedBox(height: 14),
          Center(
            child: SelectableText(
              r.recoveredKey!,
              style: const TextStyle(
                fontFamilyFallback: _monoFallback,
                fontSize: 26,
                letterSpacing: 3,
                fontWeight: FontWeight.w700,
                color: Color(0xFF4ADE80),
              ),
            ),
          ),
          if ((r.recoveredLabel ?? '').isNotEmpty) ...[
            const SizedBox(height: 8),
            Center(
              child: Text('来源标记：${r.recoveredLabel}',
                  style: theme.textTheme.bodySmall),
            ),
          ],
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () {
                    // mfoc / Proxmark 的字典里使用小写十六进制更常见，这里两种都给
                    Clipboard.setData(ClipboardData(text: r.recoveredKey!));
                    _snack('已复制密钥 ${r.recoveredKey}');
                  },
                  icon: const Icon(Icons.copy, size: 16),
                  label: const Text('复制密钥'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () {
                    Clipboard.setData(
                        ClipboardData(text: r.recoveredKey!.toLowerCase()));
                    _snack('已复制小写密钥');
                  },
                  icon: const Icon(Icons.text_fields, size: 16),
                  label: const Text('复制小写'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            '拿到这把 Key A 之后，用 nested 攻击就能把这张卡其余扇区的密钥'
            '全部展开（Proxmark3：hf mf autopwn）。',
            style: theme.textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  Widget _nonceListCard(ThemeData theme, List<MifareNonceRecord> records) {
    String h(int v) => v.toRadixString(16).padLeft(8, '0');
    return _section(
      theme: theme,
      child: ExpansionTile(
        tilePadding: EdgeInsets.zero,
        childrenPadding: EdgeInsets.zero,
        shape: const Border(),
        collapsedShape: const Border(),
        title: Text('nonce 记录（${records.length} 组）',
            style: theme.textTheme.titleMedium),
        children: [
          for (var i = 0; i < records.length; i++)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '第 ${i + 1} 组${records[i].label.isEmpty ? '' : ' · ${records[i].label}'}',
                    style: TextStyle(
                        fontSize: 12, color: theme.colorScheme.primary),
                  ),
                  const SizedBox(height: 4),
                  SelectableText(
                    'uid ${h(records[i].uid)}\n'
                    'nt0 ${h(records[i].nt0)}  nr0 ${h(records[i].nr0)}  ar0 ${h(records[i].ar0)}\n'
                    'nt1 ${h(records[i].nt1)}  nr1 ${h(records[i].nr1)}  ar1 ${h(records[i].ar1)}',
                    style: TextStyle(
                      fontFamilyFallback: _monoFallback,
                      fontSize: 11.5,
                      height: 1.5,
                      color: theme.textTheme.bodySmall?.color,
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  // ---------- 通用小部件 ----------

  Widget _pickCard({
    required ThemeData theme,
    required IconData icon,
    required String title,
    required String subtitle,
    required String buttonLabel,
    required bool busy,
    required VoidCallback onPick,
    required Future<void> Function(String) onDrop,
  }) {
    final state = context.read<AppState>();
    final accent = theme.colorScheme.primary;
    final card = _cardColor(theme);

    final inner = Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 20),
      decoration: BoxDecoration(
        color: _hovering ? accent.withOpacity(0.08) : card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: _hovering ? accent : accent.withOpacity(0.35),
          width: _hovering ? 2 : 1.5,
        ),
      ),
      child: Column(
        children: [
          Icon(busy ? Icons.hourglass_top : icon, size: 36, color: accent),
          const SizedBox(height: 12),
          Text(title, style: theme.textTheme.titleMedium),
          const SizedBox(height: 4),
          Text(subtitle,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: busy ? null : onPick,
            icon: const Icon(Icons.folder_open, size: 20),
            label: Text(buttonLabel),
          ),
          if (state.isPcMode) ...[
            const SizedBox(height: 8),
            Text('也可以把文件直接拖到这里',
                style: theme.textTheme.bodySmall),
          ],
        ],
      ),
    );

    if (!state.isPcMode) return inner;
    return DropTarget(
      onDragEntered: (_) => setState(() => _hovering = true),
      onDragExited: (_) => setState(() => _hovering = false),
      onDragDone: (detail) {
        setState(() => _hovering = false);
        for (final f in detail.files) {
          onDrop(f.path);
        }
      },
      child: inner,
    );
  }

  Widget _pathLine(ThemeData theme, String path) => Row(
        children: [
          const Icon(Icons.description_outlined, size: 15),
          const SizedBox(width: 6),
          Expanded(
            child: SelectableText(
              path,
              maxLines: 2,
              style: theme.textTheme.bodySmall,
            ),
          ),
        ],
      );

  Widget _section({required ThemeData theme, required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: _cardColor(theme),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: theme.brightness == Brightness.dark
              ? const Color(0xFF2A3350)
              : const Color(0xFFE3E8F0),
        ),
      ),
      child: child,
    );
  }

  Widget _textCard({
    required ThemeData theme,
    required IconData icon,
    required String title,
    required String body,
  }) {
    return _section(
      theme: theme,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 18, color: theme.colorScheme.primary),
              const SizedBox(width: 8),
              Text(title, style: theme.textTheme.titleMedium),
              const Spacer(),
              IconButton(
                tooltip: '复制',
                icon: const Icon(Icons.copy, size: 16),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: body));
                  _snack('已复制「$title」');
                },
              ),
            ],
          ),
          const SizedBox(height: 8),
          SelectableText(
            body,
            style: TextStyle(
              fontFamilyFallback: _monoFallback,
              fontSize: 12,
              height: 1.55,
              color: theme.colorScheme.onSurface,
            ),
          ),
        ],
      ),
    );
  }

  Widget _kv(ThemeData theme, String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 88,
              child: Text(k, style: theme.textTheme.bodySmall),
            ),
            Expanded(
              child: SelectableText(
                v,
                style: TextStyle(
                  fontFamilyFallback: _monoFallback,
                  fontSize: 13,
                  color: theme.colorScheme.onSurface,
                ),
              ),
            ),
          ],
        ),
      );

  Widget _pill(ThemeData theme, String text, Color color) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: color.withOpacity(0.12),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: color.withOpacity(0.4)),
        ),
        child: Text(text, style: TextStyle(fontSize: 12, color: color)),
      );

  Widget _errorBox(ThemeData theme, String msg) => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFFF87171).withOpacity(0.08),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFFF87171).withOpacity(0.35)),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.error_outline, size: 20, color: Color(0xFFF87171)),
            const SizedBox(width: 10),
            Expanded(
              child: SelectableText(
                msg,
                style: const TextStyle(fontSize: 13, height: 1.5),
              ),
            ),
          ],
        ),
      );

  static String _hexOrQuestion(List<int>? v) => v == null
      ? '??'
      : v.map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join();
}

/// 安全地取卡片背景色。
///
/// 不能直接写 `theme.cardTheme.color as Color`：如果某处只套了一个不带
/// cardTheme 的 MaterialApp（测试里很常见），这里会取到 null 然后崩掉。
Color _cardColor(ThemeData theme) =>
    theme.cardTheme.color ?? theme.colorScheme.surface;
