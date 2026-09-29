import 'dart:convert';
import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import '../models/brute_force.dart';
import '../models/task.dart';
import '../utils/platform_utils.dart';
import 'task_orchestrator.dart';
import 'dict_service.dart';

class ServerInfo {
  final String host;
  final int port;
  final bool running;
  ServerInfo({this.host = '', this.port = 0, this.running = false});
}

class ServerService {
  final TaskOrchestrator orchestrator;
  final DictService dictService;
  final int port;
  final String uploadDir;
  final String hashcatPath;
  HttpServer? _server;

  ServerService({
    required this.orchestrator,
    required this.dictService,
    this.port = 8787,
    required this.uploadDir,
    required this.hashcatPath,
  });

  bool get isRunning => _server != null;

  Future<ServerInfo> start() async {
    if (_server != null) {
      return ServerInfo(
          host: _server!.address.host, port: _server!.port, running: true);
    }
    await Directory(uploadDir).create(recursive: true);
    final handler = const Pipeline()
        .addMiddleware(_corsMiddleware())
        .addHandler(_router);
    _server = await shelf_io.serve(handler, '0.0.0.0', port);
    return ServerInfo(
        host: _server!.address.host,
        port: _server!.port,
        running: true);
  }

  Future<void> stop() async {
    await _server?.close(force: true);
    _server = null;
  }

  String get localIp => _server?.address.host ?? '';

  Middleware _corsMiddleware() => (Handler inner) => (Request req) async {
        final res = await inner(req);
        return res.change(headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        });
      };

  Future<Response> _router(Request req) async {
    if (req.method == 'OPTIONS') {
      return Response.ok('', headers: {'Access-Control-Allow-Origin': '*'});
    }
    final path = req.url.path;
    final segs = path.split('/').where((s) => s.isNotEmpty).toList();

    if (segs.isEmpty) {
      return _json({'service': 'HashCrack PC', 'ok': true});
    }
    if (segs.first == 'api') {
      if (segs.length < 2) return _json({'endpoints': _endpoints()});

      switch (segs[1]) {
        case 'info':
          return _info();
        case 'tasks':
          if (req.method == 'GET') return _listTasks();
          if (req.method == 'POST') return _upload(req);
          return _methodNotAllowed();
        case 'task':
          if (segs.length >= 4 && segs[3] == 'cancel' && req.method == 'POST') {
            return _cancel(segs[2]);
          }
          if (segs.length >= 4 &&
              segs[3] == 'bruteforce' &&
              req.method == 'POST') {
            return _bruteForce(req, segs[2]);
          }
          if (segs.length >= 3 && req.method == 'GET') {
            return _taskDetail(segs[2]);
          }
          return _notFound();
        case 'dicts':
          if (req.method == 'GET') return _listDicts();
          return _methodNotAllowed();
        default:
          return _notFound();
      }
    }
    return _notFound();
  }

  Response _info() => _json({
        'platform': PlatformUtils.currentPlatformLabel,
        'canRunHashcat': PlatformUtils.canRunHashcatLocally,
        'hashcatPath': hashcatPath,
        'appVersion': '1.0.0',
        'serverTime': DateTime.now().toIso8601String(),
      });

  Response _listTasks() {
    final tasks = orchestrator.allTasks.map((t) => t.toMap()).toList();
    return _json({'tasks': tasks, 'count': tasks.length});
  }

  Future<Response> _upload(Request req) async {
    try {
      final body = await req.readAsString();
      final data = jsonDecode(body) as Map<String, dynamic>;
      final fileName = data['fileName'] as String? ?? 'upload.bin';
      final b64 = data['fileBase64'] as String? ?? '';
      if (b64.isEmpty) {
        return _json({'error': 'fileBase64 为空'}, status: 400);
      }
      final bytes = base64Decode(b64);
      if (bytes.length > 100 * 1024 * 1024) {
        return _json({'error': '文件过大（>100MB）'}, status: 400);
      }
      final safeName = fileName.replaceAll(RegExp(r'[^\w.\-]'), '_');
      final savePath = '$uploadDir${Platform.pathSeparator}'
          '${DateTime.now().millisecondsSinceEpoch}_$safeName';
      await File(savePath).writeAsBytes(bytes);
      final task = await orchestrator.submit(savePath, originalName: fileName);
      return _json({'taskId': task.id, 'fileName': task.fileName});
    } catch (e) {
      return _json({'error': '上传失败: $e'}, status: 500);
    }
  }

  Response _taskDetail(String id) {
    final task = orchestrator.getTask(id);
    if (task == null) return _json({'error': '任务不存在'}, status: 404);
    return _json(task.toMap());
  }

  Response _cancel(String id) {
    orchestrator.cancel(id);
    return _json({'ok': true, 'taskId': id});
  }

  /// 手机端发起暴力破解。只传字符集与长度，哈希早已在 PC 上，无需重传文件。
  Future<Response> _bruteForce(Request req, String id) async {
    final task = orchestrator.getTask(id);
    if (task == null) return _json({'error': '任务不存在'}, status: 404);
    if (task.hashValue.isEmpty) {
      return _json({'error': '该任务尚未提取到哈希，无法暴力破解'}, status: 400);
    }
    if (task.status.isRunning) {
      return _json({'error': '任务正在运行中'}, status: 409);
    }
    try {
      final body = await req.readAsString();
      final data = body.trim().isEmpty
          ? <String, dynamic>{}
          : jsonDecode(body) as Map<String, dynamic>;
      final charset = CharsetPreset.values.firstWhere(
        (e) => e.name == (data['charset'] as String? ?? ''),
        orElse: () => CharsetPreset.digits,
      );
      // 不信任客户端传来的数值：长度与时限都夹到合理区间，
      // 否则一个手改的请求就能让 PC 端跑一个永远结束不了的任务。
      final config = BruteForceConfig.normalized(
        charset: charset,
        minLen: (data['minLen'] as num?)?.toInt() ?? 1,
        maxLen: (data['maxLen'] as num?)?.toInt() ?? 8,
        runtimeSec: (data['runtimeSec'] as num?)?.toInt() ?? 0,
        // 固定前缀由 normalized/normalizePrefix 统一净化（去控制字符、限长）
        prefix: (data['prefix'] as String?) ?? '',
      );
      await orchestrator.retryWithBruteForce(id, config);
      return _json({
        'ok': true,
        'taskId': id,
        'label': config.label,
        'keyspace': config.keyspace.toString(),
      });
    } catch (e) {
      return _json({'error': '发起暴力破解失败: $e'}, status: 500);
    }
  }

  Future<Response> _listDicts() async {
    final dicts = await dictService.listDicts();
    return _json({
      'dicts': dicts
          .map((d) => {'name': d.name, 'size': d.sizeBytes, 'builtIn': d.builtIn})
          .toList()
    });
  }

  Response _json(Map<String, dynamic> body, {int status = 200}) =>
      Response(status,
          body: jsonEncode(body),
          headers: {'Content-Type': 'application/json; charset=utf-8'});

  Response _notFound() => _json({'error': 'not found'}, status: 404);

  Response _methodNotAllowed() =>
      _json({'error': 'method not allowed'}, status: 405);

  Map<String, String> _endpoints() => {
        'GET /api/info': 'PC 端信息',
        'GET /api/tasks': '任务列表',
        'POST /api/tasks': '上传文件（base64）',
        'GET /api/task/<id>': '任务详情',
        'POST /api/task/<id>/cancel': '取消任务',
        'POST /api/task/<id>/bruteforce': '对任务发起暴力破解（charset/minLen/maxLen/runtimeSec）',
        'GET /api/dicts': '字典列表',
      };
}
