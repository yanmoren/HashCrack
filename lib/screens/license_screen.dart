import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../state/license_controller.dart';

/// 授权/注册页。未激活时作为启动拦截页展示。
class LicenseScreen extends StatefulWidget {
  const LicenseScreen({super.key});

  @override
  State<LicenseScreen> createState() => _LicenseScreenState();
}

class _LicenseScreenState extends State<LicenseScreen> {
  final TextEditingController _codeCtl = TextEditingController();
  bool _busy = false;
  String? _error;
  bool _copied = false;

  @override
  void dispose() {
    _codeCtl.dispose();
    super.dispose();
  }

  Future<void> _activate() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final err = await context.read<LicenseController>().activate(_codeCtl.text);
    if (mounted) {
      setState(() {
        _busy = false;
        _error = err;
      });
      if (err == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('激活成功'),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    }
  }

  Future<void> _copyMachine() async {
    await Clipboard.setData(
        ClipboardData(text: context.read<LicenseController>().machineCode));
    if (mounted) {
      setState(() => _copied = true);
      Future.delayed(const Duration(seconds: 2), () {
        if (mounted) setState(() => _copied = false);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<LicenseController>();
    final theme = Theme.of(context);
    final code = ctrl.machineCode;

    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.verified_user_outlined,
                    size: 64, color: theme.colorScheme.primary),
                const SizedBox(height: 16),
                Text(
                  'HashCrack 授权',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.headlineSmall
                      ?.copyWith(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 8),
                Text(
                  '本软件需要激活后才能使用。\n'
                  '请把下方机器码发给作者，换取激活码填入即可。',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodyMedium,
                ),
                const SizedBox(height: 24),
                if (ctrl.loading)
                  const Center(child: CircularProgressIndicator())
                else if (code.isEmpty)
                  _corp(theme, ctrl)
                else ...[
                  Text('你的机器码', style: theme.textTheme.titleMedium),
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: theme.cardTheme.color,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: theme.colorScheme.primary),
                    ),
                    child: Column(
                      children: [
                        SelectableText(
                          code,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 22,
                            letterSpacing: 2,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          '将这段机器码发给作者',
                          style: theme.textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: _copyMachine,
                    icon: const Icon(Icons.copy, size: 18),
                    label: Text(_copied ? '已复制' : '复制机器码'),
                  ),
                  const SizedBox(height: 20),
                  TextField(
                    controller: _codeCtl,
                    autocorrect: false,
                    enableSuggestions: false,
                    textCapitalization: TextCapitalization.characters,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 16),
                    decoration: const InputDecoration(
                      labelText: '激活码',
                      hintText: 'XXXXXX-XXXXXX-XXXXXX-XXXXXX',
                      border: OutlineInputBorder(
                          borderRadius:
                              BorderRadius.all(Radius.circular(12))),
                    ),
                  ),
                  const SizedBox(height: 12),
                  if (_error != null)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: Text(
                        _error!,
                        textAlign: TextAlign.center,
                        style: const TextStyle(color: Color(0xFFF87171)),
                      ),
                    ),
                  FilledButton(
                    onPressed: _busy ? null : _activate,
                    child: Text(_busy ? '校验中…' : '激活'),
                  ),
                ],
                const SizedBox(height: 16),
                Text(
                  '激活码一台机器一个，换设备/重做系统后需重新激活。',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // 机器码采集失败时的兜底提示
  Widget _corp(ThemeData theme, LicenseController ctrl) {
    return Column(
      children: [
        Text('无法采集本机机器码',
            style: theme.textTheme.titleMedium,
            textAlign: TextAlign.center),
        const SizedBox(height: 8),
        Text(ctrl.initError ?? '',
            textAlign: TextAlign.center, style: theme.textTheme.bodySmall),
        const SizedBox(height: 12),
        FilledButton.tonalIcon(
          onPressed: ctrl.reloadMachine,
          icon: const Icon(Icons.refresh),
          label: const Text('重试'),
        ),
      ],
    );
  }
}