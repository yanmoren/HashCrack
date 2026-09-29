import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

class DropZone extends StatefulWidget {
  final void Function(String path) onFile;
  final bool isPcMode;
  final bool busy;

  const DropZone({
    super.key,
    required this.onFile,
    required this.isPcMode,
    this.busy = false,
  });

  @override
  State<DropZone> createState() => _DropZoneState();
}

class _DropZoneState extends State<DropZone> {
  bool _hovering = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;
    // 不要写 `theme.cardTheme.color as Color`：某些主题没有配 cardTheme，
    // 这里会取到 null 然后强转崩溃（MIFARE 页面已经踩过一次）。
    final card = theme.cardTheme.color ?? theme.colorScheme.surface;

    final inner = Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(vertical: 48, horizontal: 24),
      decoration: BoxDecoration(
        color: _hovering
            ? accent.withOpacity(0.08)
            : card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: _hovering ? accent : accent.withOpacity(0.35),
          width: _hovering ? 2 : 1.5,
          style: BorderStyle.solid,
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 64,
            height: 64,
            decoration: BoxDecoration(
              color: accent.withOpacity(0.12),
              shape: BoxShape.circle,
            ),
            child: Icon(
              widget.busy ? Icons.hourglass_top : Icons.cloud_upload_rounded,
              size: 32,
              color: accent,
            ),
          ),
          const SizedBox(height: 16),
          Text(
            widget.busy ? '处理中…' : '拖拽文件到此处',
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 6),
          Text(
            widget.isPcMode
                ? '压缩包 / 文档 / WiFi / 密钥 / 加密磁盘 / 钱包 / 哈希 —— 自动识别'
                : '支持 40+ 种加密文件与哈希文本，自动识别',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 18),
          FilledButton.icon(
            onPressed: widget.busy ? null : _pickFile,
            icon: const Icon(Icons.folder_open, size: 20),
            label: const Text('选择文件'),
          ),
        ],
      ),
    );

    if (!widget.isPcMode) {
      return inner;
    }
    return DropTarget(
      onDragEntered: (_) => setState(() => _hovering = true),
      onDragExited: (_) => setState(() => _hovering = false),
      onDragDone: (detail) {
        setState(() => _hovering = false);
        for (final f in detail.files) {
          widget.onFile(f.path);
        }
      },
      child: inner,
    );
  }

  Future<void> _pickFile() async {
    // 用 FileType.any 而不是逐个列扩展名：能识别的类型已经有 40 多种，
    // 靠白名单过滤只会让用户遇到「文件明明在却选不中」。
    // 识别交给 FileIdentifier，不靠文件选择器。
    //
    // file_picker 12.x 起改为静态方法，且直接返回 List<PlatformFile>
    // （取消时返回空列表，不再是 null）
    final files = await FilePicker.pickFiles(type: FileType.any);
    if (files.isEmpty) return;
    for (final f in files) {
      final p = f.path;
      if (p != null && p.isNotEmpty) widget.onFile(p);
    }
  }
}
