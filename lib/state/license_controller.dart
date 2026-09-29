import 'package:flutter/foundation.dart';
import '../services/license_service.dart';

/// 授权状态控制器，连接 LicenseService 与 UI。
class LicenseController extends ChangeNotifier {
  final LicenseService _svc = LicenseService.instance;

  bool _loading = true;
  String? _initError;

  bool get loading => _loading;
  String? get initError => _initError;
  bool get isActivated => !_loading && _svc.isActivated;
  String get machineCode => _svc.displayMachineCode;

  /// 启动时初始化（采集机器码 + 校验已保存激活码）。
  Future<void> init() async {
    _loading = true;
    _initError = await _svc.init();
    _loading = false;
    notifyListeners();
  }

  /// 用用户输入的激活码激活。返回 null 表示成功。
  Future<String?> activate(String code) async {
    final err = await _svc.activate(code);
    if (err == null) notifyListeners();
    return err;
  }

  /// 采集失败时重试。
  Future<void> reloadMachine() async {
    _loading = true;
    notifyListeners();
    _initError = await _svc.init();
    _loading = false;
    notifyListeners();
  }
}