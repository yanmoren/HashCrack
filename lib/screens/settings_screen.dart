import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';
import '../services/hashcat_service.dart';
import '../utils/constants.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _hashcatCtrl;
  late TextEditingController _toolsCtrl;
  late TextEditingController _hostCtrl;
  late TextEditingController _portCtrl;
  String? _testMsg;

  @override
  void initState() {
    super.initState();
    final s = context.read<AppState>();
    _hashcatCtrl = TextEditingController(text: s.hashcatPath);
    _toolsCtrl = TextEditingController(text: s.userToolsDir);
    _hostCtrl = TextEditingController(text: s.pcHost);
    _portCtrl = TextEditingController(text: '${s.pcPort}');
  }

  @override
  void dispose() {
    _hashcatCtrl.dispose();
    _toolsCtrl.dispose();
    _hostCtrl.dispose();
    _portCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('设置')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _infoCard(state, theme),
          const SizedBox(height: 16),
          if (state.isPcMode) ..._pcSettings(state, theme),
          if (!state.isPcMode) ..._mobileSettings(state, theme),
          const SizedBox(height: 16),
          _about(theme),
        ],
      ),
    );
  }

  Widget _infoCard(AppState state, ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Icon(state.isPcMode ? Icons.computer : Icons.phone_android,
                color: theme.colorScheme.primary),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                      state.isPcMode
                          ? 'PC 端 · 本地执行'
                          : '移动端 · 远程连接',
                      style: theme.textTheme.titleMedium),
                  Text(
                    state.isPcMode
                        ? 'hashcat 在本机运行，手机可连接'
                        : '通过局域网连接 PC 执行破解',
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _pcSettings(AppState state, ThemeData theme) {
    return [
      Text('hashcat 路径', style: theme.textTheme.titleMedium),
      const SizedBox(height: 4),
      Text('留空则自动使用软件自带的 runtime\\hashcat 内核',
          style: theme.textTheme.bodySmall),
      const SizedBox(height: 8),
      TextField(
        controller: _hashcatCtrl,
        decoration: InputDecoration(
          hintText: '留空 = 使用内置内核',
          suffixIcon: IconButton(
            icon: const Icon(Icons.folder_open),
            onPressed: () async {
              // file_picker 12.x：静态方法，返回 List<PlatformFile>
              final files = await FilePicker.pickFiles(
                type: FileType.custom,
                allowedExtensions: ['exe', 'bin'],
              );
              if (files.isNotEmpty) {
                final p = files.first.path;
                if (p != null) _hashcatCtrl.text = p;
              }
            },
          ),
        ),
      ),
      const SizedBox(height: 12),
      FilledButton(
        onPressed: () => state.setHashcatPath(_hashcatCtrl.text.trim()),
        child: const Text('保存路径'),
      ),
      const SizedBox(height: 24),
      Text('提取工具目录', style: theme.textTheme.titleMedium),
      const SizedBox(height: 4),
      Text('zip2john / pdf2john / office2john / hcxpcaptool 所在目录；'
          '留空则使用软件自带的 runtime\\tools',
          style: theme.textTheme.bodySmall),
      const SizedBox(height: 8),
      TextField(
        controller: _toolsCtrl,
        decoration: InputDecoration(
          hintText: '留空 = 使用内置工具',
          suffixIcon: IconButton(
            icon: const Icon(Icons.folder_open),
            onPressed: () async {
              final r = await FilePicker.getDirectoryPath();
              if (r != null) _toolsCtrl.text = r;
            },
          ),
        ),
      ),
      const SizedBox(height: 12),
      FilledButton(
        onPressed: () => state.setToolsDir(_toolsCtrl.text.trim()),
        child: const Text('保存工具目录'),
      ),
      const SizedBox(height: 24),
      Text('服务端口', style: theme.textTheme.titleMedium),
      const SizedBox(height: 8),
      TextField(
        controller: _portCtrl,
        keyboardType: TextInputType.number,
        decoration: const InputDecoration(hintText: '8787'),
      ),
      const SizedBox(height: 16),
      _sectionLabel(theme, '字典管理'),
      const SizedBox(height: 8),
      FilledButton.tonalIcon(
        onPressed: () async {
          final files = await FilePicker.pickFiles(
            type: FileType.custom,
            allowedExtensions: ['txt', 'dict', 'lst'],
          );
          if (files.isNotEmpty) {
            final p = files.first.path;
            if (p != null) {
              await state.addDict(p);
              _snack('已添加字典');
            }
          }
        },
        icon: const Icon(Icons.post_add),
        label: const Text('添加用户字典'),
      ),
      const SizedBox(height: 4),
      Text('提示：直接把 .txt 字典文件放进软件的 runtime\\dicts 目录，'
          '重启后也会自动加载',
          style: theme.textTheme.bodySmall),
      const SizedBox(height: 24),
      _sectionLabel(theme, '自动策略时长'),
      const SizedBox(height: 8),
      Text('自动流程里「单组掩码」最多跑多久。'
          'WPA 握手包这类慢哈希在普通机器上只有几万 H/s，'
          '3 分钟连 8 位数字的零头都跑不完，会被截断后误报「所有策略均未命中」。',
          style: theme.textTheme.bodySmall),
      const SizedBox(height: 10),
      Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          for (final e in AppConstants.maskRuntimeLimitOptions.entries)
            ChoiceChip(
              label: Text(e.value, style: const TextStyle(fontSize: 12)),
              selected: state.maskRuntimeLimitSec == e.key,
              onSelected: (_) async {
                await state.setMaskRuntimeLimit(e.key);
                _snack('已设置：${e.value}');
              },
            ),
        ],
      ),
      const SizedBox(height: 8),
      Text('需要长时间穷举时，建议改用任务上的「暴力破解」入口——'
          '它会先算出组合空间与预计耗时，再决定要不要开跑。',
          style: theme.textTheme.bodySmall),
      const SizedBox(height: 24),
      _sectionLabel(theme, '运行环境自检'),
      const SizedBox(height: 8),
      Card(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: SelectableText(
            state.environmentReport,
            style: theme.textTheme.bodySmall,
          ),
        ),
      ),
      const SizedBox(height: 8),
      FilledButton.tonalIcon(
        onPressed: () async {
          final report =
              await HashcatService.checkEnvironment(state.effectiveHashcatPath);
          if (!mounted) return;
          _showEnvDialog(report);
        },
        icon: const Icon(Icons.memory),
        label: const Text('检测显卡计算后端'),
      ),
    ];
  }

  void _showEnvDialog(String report) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('计算后端检测结果'),
        content: SingleChildScrollView(child: SelectableText(report)),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }

  List<Widget> _mobileSettings(AppState state, ThemeData theme) {
    return [
      Text('PC 地址', style: theme.textTheme.titleMedium),
      const SizedBox(height: 8),
      TextField(
        controller: _hostCtrl,
        keyboardType: TextInputType.number,
        decoration: const InputDecoration(
          hintText: '如 192.168.1.100',
          prefixText: 'http://',
        ),
      ),
      const SizedBox(height: 16),
      Text('端口', style: theme.textTheme.titleMedium),
      const SizedBox(height: 8),
      TextField(
        controller: _portCtrl,
        keyboardType: TextInputType.number,
        decoration: const InputDecoration(hintText: '8787'),
      ),
      const SizedBox(height: 16),
      Row(
        children: [
          FilledButton(
            onPressed: () async {
              final host = _hostCtrl.text.trim();
              final port = int.tryParse(_portCtrl.text.trim()) ?? 8787;
              await state.setRemoteConfig(host, port);
              _snack('已保存');
            },
            child: const Text('保存配置'),
          ),
          const SizedBox(width: 12),
          OutlinedButton.icon(
            onPressed: () async {
              setState(() => _testMsg = '测试中…');
              final ok = await state.testRemoteConnection();
              setState(() => _testMsg = ok ? '连接成功' : '连接失败');
            },
            icon: const Icon(Icons.wifi_find),
            label: const Text('测试连接'),
          ),
        ],
      ),
      if (_testMsg != null)
        Padding(
          padding: const EdgeInsets.only(top: 12),
          child: Text(
            _testMsg!,
            style: TextStyle(
              color: _testMsg == '连接成功'
                  ? const Color(0xFF4ADE80)
                  : const Color(0xFFF87171),
            ),
          ),
        ),
    ];
  }

  Widget _sectionLabel(ThemeData theme, String t) => Text(t,
      style: theme.textTheme.titleMedium?.copyWith(
          color: theme.colorScheme.primary));

  Widget _about(ThemeData theme) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('关于', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            Text('HashCrack 1.0.0', style: theme.textTheme.bodyMedium),
            const SizedBox(height: 4),
            Text(
              '基于 hashcat 的图形化破解工具。\n'
              '自动识别 ZIP / PDF / Office / WiFi 握手包，'
              '提取哈希后执行字典+掩码自动策略；\n'
              '自动策略未命中时，可按字符集与长度自行发起暴力破解。',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            Text(
              '免费软件，无需激活码或授权，开箱即用。\n'
              '遵循 GPLv3 发布。',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }

  void _snack(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      behavior: SnackBarBehavior.floating,
    ));
  }
}
