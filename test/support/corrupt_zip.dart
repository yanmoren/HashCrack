import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// 测试用的压缩包破坏工具。
///
/// 放在 support/ 而不是某个 _test.dart 里：多个测试文件都要用它，
/// 而测试文件之间互相 import 会把对方的 main() 也拉进来。
///
/// 翻转 [entryName] 密文区的第一个字节。
///
/// 只对**存储方式**（`-mx=0`）的条目可靠：数据区紧跟在本地头之后，位置能直接
/// 算出来，不必解析压缩流。ZipCrypto 的 12 字节加密头之后才是有效密文。
///
/// 用途：制造"密码完全正确、但密文被动过"的包。这种包解出来的明文 CRC 必然
/// 对不上，而 7-Zip 无从分辨"密钥错"还是"密文被改过"，只会甩出一句
/// `CRC Failed in encrypted file. Wrong password?`——正是要防的歧义来源。
void flipByteInStoredEntry(String zipPath, String entryName) {
  final bytes = File(zipPath).readAsBytesSync();
  final want = entryName.codeUnits;
  for (var i = 0; i + 30 <= bytes.length; i++) {
    if (bytes[i] != 0x50 ||
        bytes[i + 1] != 0x4b ||
        bytes[i + 2] != 0x03 ||
        bytes[i + 3] != 0x04) {
      continue;
    }
    final nameLen = bytes[i + 26] | (bytes[i + 27] << 8);
    final extraLen = bytes[i + 28] | (bytes[i + 29] << 8);
    if (nameLen != want.length) continue;
    final nameStart = i + 30;
    if (nameStart + nameLen > bytes.length) continue;
    var same = true;
    for (var k = 0; k < nameLen; k++) {
      if (bytes[nameStart + k] != want[k]) {
        same = false;
        break;
      }
    }
    if (!same) continue;

    final pos = nameStart + nameLen + extraLen + 20;
    if (pos >= bytes.length) fail('条目 $entryName 的数据区越界');
    bytes[pos] ^= 0xFF;
    File(zipPath).writeAsBytesSync(bytes);
    return;
  }
  fail('未在 $zipPath 中找到存储条目 $entryName');
}