import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import '../models/brute_force.dart';
import '../models/task.dart';

class RemoteClient {
  String host;
  int port;
  Duration timeout;

  RemoteClient({this.host = '', this.port = 8787, this.timeout = const Duration(seconds: 15)});

  String get baseUrl {
    if (host.isEmpty) return '';
    return 'http://$host:$port';
  }

  bool get isConfigured => host.isNotEmpty;

  void configure(String host, int port) {
    this.host = host;
    this.port = port;
  }

  Future<Map<String, dynamic>> getInfo() async {
    final r = await http.get(Uri.parse('$baseUrl/api/info')).timeout(timeout);
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  Future<bool> ping() async {
    try {
      final r = await http.get(Uri.parse('$baseUrl/api/info')).timeout(timeout);
      return r.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  Future<List<CrackTask>> getTasks() async {
    final r = await http.get(Uri.parse('$baseUrl/api/tasks')).timeout(timeout);
    final data = jsonDecode(r.body) as Map<String, dynamic>;
    final list = data['tasks'] as List? ?? [];
    return list
        .map((e) => CrackTask.fromMap(e as Map<String, dynamic>))
        .toList();
  }

  Future<String> uploadFile(String filePath) async {
    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final b64 = base64Encode(bytes);
    final name = filePath.split(RegExp(r'[/\\]')).last;
    final r = await http
        .post(Uri.parse('$baseUrl/api/tasks'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'fileName': name, 'fileBase64': b64}))
        .timeout(timeout * 4);
    final data = jsonDecode(r.body) as Map<String, dynamic>;
    if (r.statusCode != 200) {
      throw Exception(data['error'] ?? '上传失败');
    }
    return data['taskId'] as String;
  }

  Future<CrackTask?> getTask(String id) async {
    final r =
        await http.get(Uri.parse('$baseUrl/api/task/$id')).timeout(timeout);
    if (r.statusCode == 404) return null;
    final data = jsonDecode(r.body) as Map<String, dynamic>;
    return CrackTask.fromMap(data);
  }

  Future<void> cancel(String id) async {
    await http
        .post(Uri.parse('$baseUrl/api/task/$id/cancel'))
        .timeout(timeout);
  }

  /// 让 PC 端对指定任务重新发起暴力破解。
  /// 只传字符集与长度参数，哈希本身留在 PC 上，不重复传输文件。
  Future<void> retryWithBruteForce(String id, BruteForceConfig config) async {
    final r = await http
        .post(Uri.parse('$baseUrl/api/task/$id/bruteforce'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'charset': config.charset.name,
              'minLen': config.minLen,
              'maxLen': config.maxLen,
              'runtimeSec': config.runtimeSec,
            }))
        .timeout(timeout);
    if (r.statusCode != 200) {
      final data = jsonDecode(r.body) as Map<String, dynamic>;
      throw Exception(data['error'] ?? '发起暴力破解失败');
    }
  }

  Future<List<Map<String, dynamic>>> getDicts() async {
    final r = await http.get(Uri.parse('$baseUrl/api/dicts')).timeout(timeout);
    final data = jsonDecode(r.body) as Map<String, dynamic>;
    return (data['dicts'] as List? ?? [])
        .map((e) => e as Map<String, dynamic>)
        .toList();
  }
}
