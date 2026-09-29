import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../models/archive_report.dart';

/// ZIP 结构修复器。
///
/// 职责边界：**只修结构、只搬字节**。不解压、不解密、不持有密码——
/// 加密条目的密文原样复制。因此它可以在拿到密码之前运行，
/// 也可以被任何调用方复用而不必担心密码泄露。
///
/// 修复依据：ZIP 的目录（中央目录）集中在文件末尾，一旦截断或损坏整个包就
/// "打不开"；但每条记录前面的**本地文件头**（`PK\x03\x04`）散布在文件各处、
/// 格式简单且自带签名，因此可以扫描重建。这正是 `zip -FF` 的做法。
///
/// 关于中文文件名：写回新包时**名字按原字节搬运**，编码问题由解压环节处理
/// （7-Zip 的 `-mcp=936`）。本文件不做 GBK 码表映射——Dart 核心库没有 GBK
/// 码表，硬凑一个近似映射只会给出错误的汉字，比诚实的占位符更糟。
class ZipRepairService {
  static const int _sigLocal = 0x04034b50;
  static const int _sigCentral = 0x02014b50;
  static const int _sigEocd = 0x06054b50;
  static const int _sigZip64Eocd = 0x06064b50;
  static const int _sigZip64Locator = 0x07064b50;
  static const int _sigDescriptor = 0x08074b50;

  static const int _sizeLocalHeader = 30;
  static const int _sizeCentralHeader = 46;

  /// EOCD 固定 22 字节，注释最多 65535 字节
  static const int _maxEocdSearch = 22 + 65535;

  static const int _chunk = 1 << 20;
  static const int _maxEntries = 2000000;

  /// 合法压缩方法白名单。压缩数据里出现 `PK\x03\x04` 字面量是常见现象，
  /// 只认签名必然误判，方法白名单是第一道也是最有效的过滤。
  static const Set<int> _validMethods = {0, 8, 9, 12, 14, 93, 95, 96, 97, 98, 99};

  /// 扫描并重建中央目录。
  ///
  /// [sourcePath] 只读打开，绝不会被修改。[outputPath] 是修复产物路径。
  ///
  /// 若包本身就是好的（中央目录完整且所有条目可定位），返回
  /// `attempted: false` 且**不产生输出文件**——没必要白拷一份 4.8 GB。
  static Future<RepairReport> repair(
    String sourcePath, {
    required String outputPath,
    void Function(double progress)? onProgress,
  }) async {
    final src = File(sourcePath);
    if (!await src.exists()) {
      return const RepairReport(attempted: true, error: '源文件不存在');
    }
    final total = await src.length();
    if (total < _sizeLocalHeader) {
      return const RepairReport(attempted: true, error: '文件过小，不是有效的 ZIP');
    }

    final raf = await src.open();
    try {
      // 第一步：先假设包是好的，中央目录完整就直接收工
      final healthy = await _readHealthyEntries(raf, total);
      if (healthy != null) {
        return RepairReport(
          attempted: false,
          succeeded: true,
          recoveredEntries: healthy.length,
        );
      }

      // 第二步：中央目录不可用，扫描本地头重建
      final scanned = await _scanEntries(raf, total, onProgress);
      if (scanned.isEmpty) {
        return const RepairReport(
          attempted: true,
          succeeded: false,
          error: '未找到任何可用的本地文件头，无法重建',
        );
      }

      final dropped = <FailedEntry>[];
      final usable = <_Scanned>[];
      for (final s in scanned) {
        if (s.compressedSize < 0) {
          dropped.add(FailedEntry(name: s.displayName, reason: '数据边界无法确定'));
          continue;
        }
        usable.add(s);
      }
      if (usable.isEmpty) {
        return RepairReport(
          attempted: true,
          succeeded: false,
          droppedEntries: dropped,
          error: '扫到的条目结构都不可信，未能重建出可用条目',
        );
      }

      await _writeArchive(raf, usable, outputPath, onProgress);

      // 产物自校验：重建出来的包必须能被重新解析出全部条目。
      // 少了这一步，"修复成功但产物打不开"会拖到用户侧才暴露。
      final problem = await _verifyOutput(outputPath, usable.length);
      return RepairReport(
        attempted: true,
        succeeded: problem == null,
        repairedPath: problem == null ? outputPath : null,
        recoveredEntries: problem == null ? usable.length : 0,
        droppedEntries: dropped,
        error: problem,
      );
    } on FileSystemException catch (e) {
      return RepairReport(attempted: true, error: '读写失败: ${e.message}');
    } finally {
      await raf.close();
    }
  }

  // ───────────────────────── 标准路径（包是好的） ─────────────────────────

  /// 按标准路径解析。包完整返回条目列表，否则返回 null。
  static Future<List<_Scanned>?> _readHealthyEntries(
    RandomAccessFile raf,
    int total,
  ) async {
    final eocd = await _findEocd(raf, total);
    if (eocd == null) return null;

    var cdOffset = eocd.centralDirOffset;
    var cdSize = eocd.centralDirSize;
    var count = eocd.totalEntries;

    if (eocd.needsZip64) {
      final z64 = await _readZip64Eocd(raf, eocd.offset);
      if (z64 == null) return null;
      cdOffset = z64.centralDirOffset;
      cdSize = z64.centralDirSize;
      count = z64.totalEntries;
    }

    if (cdOffset < 0 || cdSize <= 0) return null;
    if (cdOffset + cdSize > total) return null;
    if (count <= 0 || count > _maxEntries) return null;

    final body = await _readExact(raf, cdOffset, cdSize);
    if (body == null) return null;

    // 第一遍：先把中央目录读成中间结构
    final raw = <_RawCentral>[];
    var p = 0;
    for (var i = 0; i < count; i++) {
      if (p + _sizeCentralHeader > body.length) return null;
      if (_u32(body, p) != _sigCentral) return null;

      final nameLen = _u16(body, p + 28);
      final extraLen = _u16(body, p + 30);
      final commentLen = _u16(body, p + 32);
      final nameStart = p + _sizeCentralHeader;
      final extraStart = nameStart + nameLen;
      final next = extraStart + extraLen + commentLen;
      if (next > body.length || commentLen > 0xFFFF) return null;

      raw.add(_RawCentral(
        flags: _u16(body, p + 8),
        method: _u16(body, p + 10),
        modTime: _u16(body, p + 12),
        modDate: _u16(body, p + 14),
        crc32: _u32(body, p + 16),
        compressedSize: _u32(body, p + 20),
        uncompressedSize: _u32(body, p + 24),
        localOffset: _u32(body, p + 42),
        extra: Uint8List.fromList(
          Uint8List.sublistView(body, extraStart, extraStart + extraLen),
        ),
      ));
      p = next;
    }
    if (raw.isEmpty) return null;

    // 第二遍：逐条校验本地头确实在声称的位置上。
    // 「中央目录还在但指向垃圾」是极常见的损坏形态，这一关过不了就走重建。
    final out = <_Scanned>[];
    for (final r in raw) {
      final local = await _readLocalHeader(raf, r.localOffset, total);
      if (local == null) return null;

      // 尺寸与校验值以中央目录为准：它能覆盖 data descriptor 的条目
      var comp = r.compressedSize;
      var uncomp = r.uncompressedSize;
      var localOffset = r.localOffset;
      final z64 = _zip64Values(r.extra);
      if (z64 != null) {
        var i = 0;
        if (uncomp == 0xFFFFFFFF && i < z64.length) uncomp = z64[i++];
        if (comp == 0xFFFFFFFF && i < z64.length) comp = z64[i++];
        if (localOffset == 0xFFFFFFFF && i < z64.length) localOffset = z64[i++];
      }
      if (comp < 0 || local.dataStart + comp > total) return null;

      out.add(_Scanned(
        nameBytes: local.nameBytes,
        extraBytes: local.extraBytes,
        flags: r.flags & ~0x08, // 尺寸已知，写回时不再需要 data descriptor
        method: r.method,
        modTime: r.modTime,
        modDate: r.modDate,
        crc32: r.crc32,
        compressedSize: comp,
        uncompressedSize: uncomp,
        localOffset: localOffset,
        dataStart: local.dataStart,
        originalFlags: r.flags,
      ));
    }
    return out;
  }

  // ───────────────────────── 扫描重建路径 ─────────────────────────

  /// 顺序扫描本地文件头并定界。
  ///
  /// 采用**链式推进**而非逐字节全文件扫描：每成功解析一条就用它的数据长度
  /// 跳到下一条，这样压缩数据内部的签名字面量不会被误当成条目。
  /// 只有在边界不可知时才退回向后搜索。
  static Future<List<_Scanned>> _scanEntries(
    RandomAccessFile raf,
    int total,
    void Function(double)? onProgress,
  ) async {
    final out = <_Scanned>[];
    var cursor = 0;
    var guard = 0;

    while (cursor + _sizeLocalHeader <= total && guard++ < _maxEntries) {
      final hit = await _findSignature(raf, cursor, total, _sigLocal);
      if (hit < 0) break;
      onProgress?.call((hit / total).clamp(0.0, 1.0));

      final local = await _readLocalHeader(raf, hit, total);
      if (local == null) {
        cursor = hit + 1;
        continue;
      }

      final resolved = await _resolve(raf, local, total);
      if (resolved == null) {
        // 定界失败：不敢要这一条，从数据起点往后继续找下一个头
        cursor = local.dataStart + 1;
        continue;
      }

      out.add(_Scanned(
        nameBytes: local.nameBytes,
        extraBytes: local.extraBytes,
        flags: local.flags & ~0x08,
        method: local.method,
        modTime: local.modTime,
        modDate: local.modDate,
        crc32: resolved.crc32,
        compressedSize: resolved.compressedSize,
        uncompressedSize: resolved.uncompressedSize,
        localOffset: hit,
        dataStart: local.dataStart,
        originalFlags: local.flags,
      ));

      cursor = resolved.nextCursor;
    }

    onProgress?.call(1.0);
    return out;
  }

  /// 解析一个本地文件头。结构不可信时返回 null。
  static Future<_LocalHeader?> _readLocalHeader(
    RandomAccessFile raf,
    int offset,
    int total,
  ) async {
    if (offset < 0 || offset + _sizeLocalHeader > total) return null;
    final head = await _readExact(raf, offset, _sizeLocalHeader);
    if (head == null || _u32(head, 0) != _sigLocal) return null;

    final flags = _u16(head, 6);
    final method = _u16(head, 8);
    if (!_validMethods.contains(method)) return null;

    // 加密位与压缩方法必须自洽。注意这是**单向**检查：
    // 方法 99（AES）必须置加密位；但加密位配 0/8/9 是完全合法的
    // ZipCrypto（传统加密沿用原压缩方法，并不改方法号）。
    // 写成双向等价会把所有 ZipCrypto 包误判为结构不可信。
    final encrypted = (flags & 0x01) != 0;
    if (method == 99 && !encrypted) return null;

    final nameLen = _u16(head, 26);
    final extraLen = _u16(head, 28);
    if (nameLen == 0 || nameLen > 4096) return null;
    if (offset + _sizeLocalHeader + nameLen + extraLen > total) return null;

    final tail = await _readExact(raf, offset + _sizeLocalHeader, nameLen + extraLen);
    if (tail == null) return null;

    return _LocalHeader(
      flags: flags,
      method: method,
      modTime: _u16(head, 10),
      modDate: _u16(head, 12),
      crc32: _u32(head, 14),
      storedCompressedSize: _u32(head, 18),
      storedUncompressedSize: _u32(head, 22),
      nameBytes: Uint8List.fromList(Uint8List.sublistView(tail, 0, nameLen)),
      extraBytes: Uint8List.fromList(
        Uint8List.sublistView(tail, nameLen, tail.length),
      ),
      dataStart: offset + _sizeLocalHeader + nameLen + extraLen,
    );
  }

  /// 确定一条条目的数据边界与真实尺寸。
  ///
  /// 返回 null 表示无法确定——宁可丢掉这一条，也不能写出长度错误的条目：
  /// 那会让整个修复产物在解压时报错，比少一个文件更糟。
  static Future<_Resolved?> _resolve(
    RandomAccessFile raf,
    _LocalHeader local,
    int total,
  ) async {
    if (local.dataStart > total) return null;

    var crc = local.crc32;
    var comp = local.storedCompressedSize;
    var uncomp = local.storedUncompressedSize;

    // ZIP64 扩展字段里存的就是真实尺寸（本地头写 0xFFFFFFFF 时）
    final z64 = _zip64Values(local.extraBytes);
    if (z64 != null) {
      var i = 0;
      if (uncomp == 0xFFFFFFFF && i < z64.length) uncomp = z64[i++];
      if (comp == 0xFFFFFFFF && i < z64.length) comp = z64[i++];
    }

    final available = total - local.dataStart;

    // 情况零：零长度条目（目录、空文件）。
    //
    // 必须单独处理：它的数据长度为 0，下一条目的本地头就**紧贴数据起点**。
    // 若走下面的"向后找边界"，会被"紧贴起点不算边界"的守卫挡掉，进而把
    // 文件剩余部分全部误算成本条数据——一个目录条目就能吞掉整个包，
    // 重建出来的产物只剩一条巨型记录，还因为条目数自洽而谎报成功。
    if (!local.hasDataDescriptor && comp == 0) {
      return _Resolved(0, crc, uncomp, local.dataStart);
    }

    // 情况一：长度明确且无 data descriptor——直接采信。
    // 这是绝大多数真实损坏包的形态（尾部被截断，各条目头完好）。
    if (!local.hasDataDescriptor && comp > 0) {
      if (comp > available) {
        // 声明长度超出文件尾：数据被截断，有多少算多少
        return available > 0
            ? _Resolved(available, crc, uncomp, total)
            : null;
      }

      final end = local.dataStart + comp;
      if (await _looksLikeBoundary(raf, end, total)) {
        return _Resolved(comp, crc, uncomp, end);
      }

      // 落点不是任何已知边界，有两种成因：
      //   a) 本条长度是对的，只是它后面混进了不属于任何条目的孤儿数据；
      //   b) 本条长度声明过长，把后面的条目整段盖住了。
      // 盲目收紧会在 a) 情况下把好条目截断，所以必须区分：只有当声明区间
      // **内部确实存在一个结构自洽的本地头**时，才认定是 b) 并收紧到它。
      final covered = await _findCoveredEntry(raf, local.dataStart, end, total);
      if (covered != null) {
        return _Resolved(covered - local.dataStart, crc, uncomp, covered);
      }
      return _Resolved(comp, crc, uncomp, end);
    }

    // 情况二：长度未知（bit 3 或写 0）——向后找边界
    final boundary = await _findNextBoundary(raf, local.dataStart, total);
    if (boundary == null) {
      return available > 0 ? _Resolved(available, crc, uncomp, total) : null;
    }

    final size = boundary.offset - local.dataStart;
    if (size <= 0) return null;

    if (boundary.isDescriptor) {
      final desc = await _readDescriptor(raf, boundary.offset, size);
      if (desc == null) return null;
      // data descriptor 里的值与真实数据长度自校验过，比本地头可靠
      return _Resolved(size, desc.crc, desc.uncompressedSize, desc.end);
    }

    return _Resolved(size, crc, uncomp, boundary.offset);
  }

  /// 判断 [offset] 处是否落在某个已知结构边界上。
  ///
  /// 用来验证"本条声明的数据长度"是否真的指向下一条目——健康包里必然如此。
  /// 落点若不是边界，就说明长度声明不可信，需要收紧。
  static Future<bool> _looksLikeBoundary(
    RandomAccessFile raf,
    int offset,
    int total,
  ) async {
    if (offset == total) return true; // 数据一直延伸到文件尾，合法
    if (offset < 0 || offset + 4 > total) return false;
    final buf = await _readExact(raf, offset, 4);
    if (buf == null) return false;
    final v = _u32(buf, 0);
    return v == _sigLocal ||
        v == _sigCentral ||
        v == _sigEocd ||
        v == _sigZip64Eocd ||
        v == _sigZip64Locator ||
        v == _sigDescriptor;
  }

  /// 在 `[from, to)` 区间内寻找一个"被盖住的"本地文件头。
  ///
  /// 判定标准是**双重自洽**：候选头本身要能解析，且它声明的数据落点也必须
  /// 落在已知边界上（或延伸到文件尾）。只看签名会把压缩/加密数据里偶然
  /// 出现的 `PK\x03\x04` 当成条目——那会让本来完好的条目被无端截断。
  static Future<int?> _findCoveredEntry(
    RandomAccessFile raf,
    int from,
    int to,
    int total,
  ) async {
    var cursor = from + 1;
    var guard = 0;
    while (cursor + _sizeLocalHeader <= to && guard++ < 64) {
      final hit = await _findSignature(raf, cursor, to, _sigLocal);
      if (hit < 0) return null;

      final candidate = await _readLocalHeader(raf, hit, total);
      if (candidate != null) {
        final comp = candidate.storedCompressedSize;
        if (!candidate.hasDataDescriptor && comp == 0) return hit;
        if (comp > 0) {
          final end = candidate.dataStart + comp;
          if (end >= total || await _looksLikeBoundary(raf, end, total)) {
            return hit;
          }
        }
      }
      cursor = hit + 1;
    }
    return null;
  }

  /// 从 [from] 起寻找下一个边界：下一个本地头 / 中央目录头 / 数据描述符。
  /// 每个候选都必须能解析成合理结构才算数。
  static Future<_Boundary?> _findNextBoundary(
    RandomAccessFile raf,
    int from,
    int total,
  ) async {
    var cursor = from;
    var guard = 0;

    while (cursor + 4 <= total && guard++ < _maxEntries) {
      var best = -1;
      var bestSig = 0;
      for (final sig in const [_sigLocal, _sigCentral, _sigDescriptor]) {
        final hit = await _findSignature(raf, cursor, total, sig);
        if (hit < 0) continue;
        if (best < 0 || hit < best) {
          best = hit;
          bestSig = sig;
        }
      }
      if (best < 0) return null;
      if (best == from) return null; // 紧贴数据起点，不可能是边界

      if (bestSig == _sigDescriptor) return _Boundary(best, true);

      if (bestSig == _sigLocal) {
        if (await _readLocalHeader(raf, best, total) != null) {
          return _Boundary(best, false);
        }
      } else if (bestSig == _sigCentral) {
        final head = await _readExact(raf, best, _sizeCentralHeader);
        if (head != null && _plausibleCentral(head)) {
          return _Boundary(best, false);
        }
      }
      cursor = best + 1;
    }
    return null;
  }

  static bool _plausibleCentral(Uint8List head) {
    if (_u32(head, 0) != _sigCentral) return false;
    if (!_validMethods.contains(_u16(head, 10))) return false;
    final nameLen = _u16(head, 28);
    if (nameLen == 0 || nameLen > 4096) return false;
    if (_u16(head, 30) > 0xFFFF || _u16(head, 32) > 0xFFFF) return false;
    final diskStart = _u16(head, 34);
    if (diskStart != 0 && diskStart != 0xFFFF) return false;
    return true;
  }

  /// 读取数据描述符。
  ///
  /// 描述符有带签名和不带签名两种，尺寸段又可能是 32 位或 64 位。
  /// 用"压缩后长度必须等于实际数据长度"来自校验——这是唯一能确定位数的事实。
  static Future<_Descriptor?> _readDescriptor(
    RandomAccessFile raf,
    int at,
    int actualSize,
  ) async {
    final buf = await _readExact(raf, at, 24);
    if (buf == null || _u32(buf, 0) != _sigDescriptor) return null;

    final crc = _u32(buf, 4);
    final comp32 = _u32(buf, 8);
    final uncomp32 = _u32(buf, 12);
    if (comp32 == actualSize) {
      return _Descriptor(crc, uncomp32, 16, at + 16);
    }
    final comp64 = _u64(buf, 8);
    if (comp64 == actualSize) {
      return _Descriptor(crc, _u64(buf, 16), 24, at + 24);
    }
    return null;
  }

  // ───────────────────────── EOCD ─────────────────────────

  static Future<_Eocd?> _findEocd(RandomAccessFile raf, int total) async {
    final searchLen = total < _maxEocdSearch ? total : _maxEocdSearch;
    final start = total - searchLen;
    final buf = await _readExact(raf, start, searchLen);
    if (buf == null) return null;

    // 从后往前找：注释里可能藏着一个伪造的 EOCD，最后一个才是真的
    for (var i = buf.length - 22; i >= 0; i--) {
      if (_u32(buf, i) != _sigEocd) continue;
      final commentLen = _u16(buf, i + 20);
      if (i + 22 + commentLen != buf.length) continue;

      final diskNum = _u16(buf, i + 4);
      final cdDisk = _u16(buf, i + 6);
      // 多卷包不支持——本项目只处理单文件包
      if (diskNum != 0 && diskNum != 0xFFFF) continue;
      if (cdDisk != 0 && cdDisk != 0xFFFF) continue;

      final entriesOnDisk = _u16(buf, i + 8);
      final totalEntries = _u16(buf, i + 10);
      final cdSize = _u32(buf, i + 12);
      final cdOffset = _u32(buf, i + 16);

      return _Eocd(
        offset: start + i,
        centralDirOffset: cdOffset,
        centralDirSize: cdSize,
        totalEntries: entriesOnDisk == totalEntries ? totalEntries : entriesOnDisk,
        needsZip64: cdOffset == 0xFFFFFFFF ||
            cdSize == 0xFFFFFFFF ||
            totalEntries == 0xFFFF,
      );
    }
    return null;
  }

  static Future<_Zip64Eocd?> _readZip64Eocd(
    RandomAccessFile raf,
    int eocdOffset,
  ) async {
    if (eocdOffset < 20) return null;
    final loc = await _readExact(raf, eocdOffset - 20, 20);
    if (loc == null || _u32(loc, 0) != _sigZip64Locator) return null;

    final z64Offset = _u64(loc, 8);
    final rec = await _readExact(raf, z64Offset, 56);
    if (rec == null || _u32(rec, 0) != _sigZip64Eocd) return null;

    return _Zip64Eocd(
      centralDirOffset: _u64(rec, 48),
      centralDirSize: _u64(rec, 40),
      totalEntries: _u64(rec, 32),
    );
  }

  // ───────────────────────── 写出新包 ─────────────────────────

  static Future<void> _writeArchive(
    RandomAccessFile src,
    List<_Scanned> entries,
    String outputPath,
    void Function(double)? onProgress,
  ) async {
    final out = File(outputPath);
    await out.parent.create(recursive: true);

    var grandTotal = 0;
    for (final e in entries) {
      grandTotal += e.compressedSize;
    }

    final sink = await out.open(mode: FileMode.write);
    try {
      final written = <_Written>[];
      var offset = 0;
      var processed = 0;

      for (final e in entries) {
        // 重写本地头：清掉 bit 3（尺寸现在已知），其余标志位原样保留
        final zip64 = e.compressedSize >= 0xFFFFFFFF ||
            e.uncompressedSize >= 0xFFFFFFFF;
        final extra = _rebuildExtra(e.extraBytes, zip64, e);

        final header = _buildLocalHeader(e, extra: extra);
        await sink.writeFrom(header, 0, header.length);

        final dataStart = offset + header.length;
        await _copyRange(src, sink, e.dataStart, e.compressedSize);

        written.add(_Written(
          entry: e,
          extra: extra,
          localOffset: offset,
        ));

        offset = dataStart + e.compressedSize;
        processed += e.compressedSize;
        if (grandTotal > 0) {
          onProgress?.call((processed / grandTotal).clamp(0.0, 1.0));
        }
      }

      final cdStart = offset;
      var cdSize = 0;
      for (final w in written) {
        final rec = _buildCentralHeader(w);
        await sink.writeFrom(rec, 0, rec.length);
        cdSize += rec.length;
      }

      final needZip64 = written.length > 0xFFFF ||
          cdStart >= 0xFFFFFFFF ||
          cdSize >= 0xFFFFFFFF ||
          written.any((w) => w.entry.needsZip64);

      if (needZip64) {
        final rec = _buildZip64Eocd(written.length, cdSize, cdStart);
        await sink.writeFrom(rec, 0, rec.length);
        final loc = _buildZip64Locator(cdStart + cdSize);
        await sink.writeFrom(loc, 0, loc.length);
      }

      final eocd = _buildEocd(
        count: written.length,
        cdSize: cdSize,
        cdOffset: cdStart,
        zip64: needZip64,
      );
      await sink.writeFrom(eocd, 0, eocd.length);
      await sink.flush();
    } finally {
      await sink.close();
    }
  }

  /// 产物自校验：重新解析一遍，条目数对不上即判定失败。
  ///
  /// 「修复成功但产物打不开」是最坏的结局——用户以为救回来了，
  /// 很久以后才发现文件是坏的。宁可在这里失败并如实报告。
  static Future<String?> _verifyOutput(String path, int expected) async {
    final f = File(path);
    if (!await f.exists()) return '产物未生成';

    final raf = await f.open();
    try {
      final entries = await _readHealthyEntries(raf, await f.length());
      if (entries == null) return '产物自校验失败：无法解析新建的中央目录';
      if (entries.length != expected) {
        return '产物自校验失败：预期 $expected 条，解析出 ${entries.length} 条';
      }
      return null;
    } on FileSystemException catch (e) {
      return '产物自校验读写失败: ${e.message}';
    } finally {
      await raf.close();
    }
  }

  /// 流式复制一段字节。**绝不整段读入内存**——项目已有教训：
  /// zip2john.py 原先整包 read() 把 4.8 GB 的包撑爆了内存。
  static Future<void> _copyRange(
    RandomAccessFile src,
    RandomAccessFile dst,
    int start,
    int length,
  ) async {
    if (length <= 0) return;
    await src.setPosition(start);
    var left = length;
    while (left > 0) {
      final want = left < _chunk ? left : _chunk;
      final buf = await src.read(want);
      if (buf.isEmpty) break;
      await dst.writeFrom(buf, 0, buf.length);
      left -= buf.length;
    }
  }

  // ───────────────────────── 结构构造 ─────────────────────────

  static Uint8List _buildLocalHeader(_Scanned e, {required Uint8List extra}) {
    final b = Uint8List(_sizeLocalHeader + e.nameBytes.length + extra.length);
    _w32(b, 0, _sigLocal);
    _w16(b, 4, 20);
    _w16(b, 6, e.flags);
    _w16(b, 8, e.method);
    _w16(b, 10, e.modTime);
    _w16(b, 12, e.modDate);
    _w32(b, 14, e.crc32);
    _w32(b, 18, e.compressedSize >= 0xFFFFFFFF ? 0xFFFFFFFF : e.compressedSize);
    _w32(b, 22, e.uncompressedSize >= 0xFFFFFFFF ? 0xFFFFFFFF : e.uncompressedSize);
    _w16(b, 26, e.nameBytes.length);
    _w16(b, 28, extra.length);
    b.setAll(_sizeLocalHeader, e.nameBytes);
    b.setAll(_sizeLocalHeader + e.nameBytes.length, extra);
    return b;
  }

  static Uint8List _buildCentralHeader(_Written w) {
    final e = w.entry;
    final name = e.nameBytes;
    final b = Uint8List(_sizeCentralHeader + name.length + w.extra.length);
    _w32(b, 0, _sigCentral);
    _w16(b, 4, 0x031E); // version made by: 3.0 / DOS
    _w16(b, 6, 20);
    _w16(b, 8, e.flags);
    _w16(b, 10, e.method);
    _w16(b, 12, e.modTime);
    _w16(b, 14, e.modDate);
    _w32(b, 16, e.crc32);
    _w32(b, 20, e.compressedSize >= 0xFFFFFFFF ? 0xFFFFFFFF : e.compressedSize);
    _w32(b, 24, e.uncompressedSize >= 0xFFFFFFFF ? 0xFFFFFFFF : e.uncompressedSize);
    _w16(b, 28, name.length);
    _w16(b, 30, w.extra.length);
    _w16(b, 32, 0); // comment len
    _w16(b, 34, 0); // disk start
    _w16(b, 36, 0); // internal attrs
    _w32(b, 38, 0); // external attrs
    _w32(b, 42, w.localOffset >= 0xFFFFFFFF ? 0xFFFFFFFF : w.localOffset);
    b.setAll(_sizeCentralHeader, name);
    b.setAll(_sizeCentralHeader + name.length, w.extra);
    return b;
  }

  /// 重建扩展字段：剔除原 ZIP64 字段（尺寸变了），按需插入新的。
  ///
  /// **其余未知扩展字段原样保留**——里面可能有 Unicode 路径（0x7075）、
  /// 精确时间戳（0x000A）等。丢掉它们会把好端端的文件名信息弄坏。
  static Uint8List _rebuildExtra(
    Uint8List original,
    bool zip64,
    _Scanned e,
  ) {
    final keep = <Uint8List>[];
    var p = 0;
    while (p + 4 <= original.length) {
      final id = _u16(original, p);
      final len = _u16(original, p + 2);
      if (p + 4 + len > original.length) break;
      if (id != 0x0001) {
        keep.add(Uint8List.fromList(Uint8List.sublistView(original, p, p + 4 + len)));
      }
      p += 4 + len;
    }

    if (!zip64) return _concat(keep);

    final values = <int>[];
    if (e.uncompressedSize >= 0xFFFFFFFF) values.add(e.uncompressedSize);
    if (e.compressedSize >= 0xFFFFFFFF) values.add(e.compressedSize);

    final block = Uint8List(4 + values.length * 8);
    _w16(block, 0, 0x0001);
    _w16(block, 2, values.length * 8);
    for (var i = 0; i < values.length; i++) {
      _w64(block, 4 + i * 8, values[i]);
    }
    return _concat([block, ...keep]);
  }

  static Uint8List _buildEocd({
    required int count,
    required int cdSize,
    required int cdOffset,
    required bool zip64,
  }) {
    final b = Uint8List(22);
    _w32(b, 0, _sigEocd);
    _w16(b, 8, zip64 ? 0xFFFF : count);
    _w16(b, 10, zip64 ? 0xFFFF : count);
    _w32(b, 12, zip64 ? 0xFFFFFFFF : cdSize);
    _w32(b, 16, zip64 ? 0xFFFFFFFF : cdOffset);
    return b;
  }

  static Uint8List _buildZip64Eocd(int count, int cdSize, int cdOffset) {
    final b = Uint8List(56);
    _w32(b, 0, _sigZip64Eocd);
    _w64(b, 4, 44);
    _w16(b, 12, 45);
    _w16(b, 14, 45);
    _w64(b, 24, count);
    _w64(b, 32, count);
    _w64(b, 40, cdSize);
    _w64(b, 48, cdOffset);
    return b;
  }

  static Uint8List _buildZip64Locator(int zip64EocdOffset) {
    final b = Uint8List(20);
    _w32(b, 0, _sigZip64Locator);
    _w64(b, 8, zip64EocdOffset);
    _w32(b, 16, 1);
    return b;
  }

  // ───────────────────────── 字节工具 ─────────────────────────

  static Future<Uint8List?> _readExact(
    RandomAccessFile f,
    int pos,
    int len,
  ) async {
    if (len < 0 || pos < 0) return null;
    await f.setPosition(pos);
    final out = Uint8List(len);
    var got = 0;
    while (got < len) {
      final chunk = await f.read(len - got);
      if (chunk.isEmpty) return null;
      out.setRange(got, got + chunk.length, chunk);
      got += chunk.length;
    }
    return out;
  }

  /// 分块查找 4 字节签名，块间保留 3 字节重叠，避免漏掉跨块签名。
  static Future<int> _findSignature(
    RandomAccessFile f,
    int from,
    int to,
    int sig,
  ) async {
    if (from < 0 || from >= to) return -1;
    final pat = Uint8List.fromList([
      sig & 0xff,
      (sig >> 8) & 0xff,
      (sig >> 16) & 0xff,
      (sig >> 24) & 0xff,
    ]);

    var pos = from;
    var carry = Uint8List(0);
    while (pos < to) {
      final want = (to - pos) < _chunk ? (to - pos) : _chunk;
      final buf = await _readExact(f, pos, want);
      if (buf == null) return -1;

      final hay = Uint8List(carry.length + buf.length)
        ..setAll(0, carry)
        ..setAll(carry.length, buf);
      final base = pos - carry.length;
      final idx = _indexOf(hay, pat);
      if (idx >= 0) return base + idx;

      carry = Uint8List.fromList(Uint8List.sublistView(hay, hay.length - 3));
      pos += want;
    }
    return -1;
  }

  static int _indexOf(Uint8List hay, Uint8List pat) {
    final last = hay.length - pat.length;
    outer:
    for (var i = 0; i <= last; i++) {
      for (var j = 0; j < pat.length; j++) {
        if (hay[i + j] != pat[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  static int _u16(Uint8List b, int p) => b[p] | (b[p + 1] << 8);

  static int _u32(Uint8List b, int p) =>
      b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24);

  static int _u64(Uint8List b, int p) {
    var v = 0;
    for (var i = 7; i >= 0; i--) {
      v = (v << 8) | b[p + i];
    }
    return v;
  }

  static void _w16(Uint8List b, int p, int v) {
    b[p] = v & 0xff;
    b[p + 1] = (v >> 8) & 0xff;
  }

  static void _w32(Uint8List b, int p, int v) {
    b[p] = v & 0xff;
    b[p + 1] = (v >> 8) & 0xff;
    b[p + 2] = (v >> 16) & 0xff;
    b[p + 3] = (v >> 24) & 0xff;
  }

  static void _w64(Uint8List b, int p, int v) {
    for (var i = 0; i < 8; i++) {
      b[p + i] = (v >> (8 * i)) & 0xff;
    }
  }

  /// 解析 ZIP64 扩展字段（id 0x0001）里的值序列，顺序为
  /// 原始大小、压缩后大小、本地头偏移（只出现被置为 0xFFFFFFFF 的那些）。
  static List<int>? _zip64Values(Uint8List extra) {
    var p = 0;
    while (p + 4 <= extra.length) {
      final id = _u16(extra, p);
      final len = _u16(extra, p + 2);
      if (p + 4 + len > extra.length) return null;
      if (id == 0x0001) {
        final vals = <int>[];
        var q = p + 4;
        while (q + 8 <= p + 4 + len) {
          vals.add(_u64(extra, q));
          q += 8;
        }
        return vals;
      }
      p += 4 + len;
    }
    return null;
  }

  static Uint8List _concat(List<Uint8List> parts) {
    var total = 0;
    for (final p in parts) {
      total += p.length;
    }
    final out = Uint8List(total);
    var at = 0;
    for (final p in parts) {
      out.setAll(at, p);
      at += p.length;
    }
    return out;
  }
}

/// 从中央目录读出的原始字段。
class _RawCentral {
  final int flags;
  final int method;
  final int modTime;
  final int modDate;
  final int crc32;
  final int compressedSize;
  final int uncompressedSize;
  final int localOffset;
  final Uint8List extra;
  _RawCentral({
    required this.flags,
    required this.method,
    required this.modTime,
    required this.modDate,
    required this.crc32,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.localOffset,
    required this.extra,
  });
}

/// 从本地文件头读出的字段。
class _LocalHeader {
  final int flags;
  final int method;
  final int modTime;
  final int modDate;
  final int crc32;
  final int storedCompressedSize;
  final int storedUncompressedSize;
  final Uint8List nameBytes;
  final Uint8List extraBytes;
  final int dataStart;

  _LocalHeader({
    required this.flags,
    required this.method,
    required this.modTime,
    required this.modDate,
    required this.crc32,
    required this.storedCompressedSize,
    required this.storedUncompressedSize,
    required this.nameBytes,
    required this.extraBytes,
    required this.dataStart,
  });

  /// 通用目的标志 bit 3：长度写在数据之后
  bool get hasDataDescriptor => (flags & 0x08) != 0;
}

/// 一条可用于重建的条目。
class _Scanned {
  final Uint8List nameBytes;
  final Uint8List extraBytes;
  final int flags;
  final int method;
  final int modTime;
  final int modDate;
  final int crc32;
  final int compressedSize;
  final int uncompressedSize;
  final int localOffset;
  final int dataStart;
  final int originalFlags;

  _Scanned({
    required this.nameBytes,
    required this.extraBytes,
    required this.flags,
    required this.method,
    required this.modTime,
    required this.modDate,
    required this.crc32,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.localOffset,
    required this.dataStart,
    required this.originalFlags,
  });

  bool get needsZip64 =>
      compressedSize >= 0xFFFFFFFF || uncompressedSize >= 0xFFFFFFFF;

  /// 供报告显示的名字。
  ///
  /// 只按 UTF-8 解码（Dart 核心库没有 GBK 码表）。解压时的中文名由
  /// 7-Zip 的 `-mcp=936` 保证；这里只用于人看的失败条目列表，
  /// 所以不做近似映射——错别字比占位符更误导。
  String get displayName {
    if ((originalFlags & 0x800) != 0) {
      return utf8.decode(nameBytes, allowMalformed: true);
    }
    return utf8.decode(nameBytes, allowMalformed: true);
  }
}

class _Resolved {
  final int compressedSize;
  final int crc32;
  final int uncompressedSize;
  final int nextCursor;
  _Resolved(this.compressedSize, this.crc32, this.uncompressedSize, this.nextCursor);
}

class _Boundary {
  final int offset;
  final bool isDescriptor;
  _Boundary(this.offset, this.isDescriptor);
}

class _Descriptor {
  final int crc;
  final int uncompressedSize;

  /// 描述符自身占用的字节数（16 或 24）
  final int length;

  /// 描述符之后的写入位置
  final int end;

  _Descriptor(this.crc, this.uncompressedSize, this.length, this.end);
}

class _Written {
  final _Scanned entry;
  final Uint8List extra;
  final int localOffset;
  _Written({required this.entry, required this.extra, required this.localOffset});
}

class _Eocd {
  final int offset;
  final int centralDirOffset;
  final int centralDirSize;
  final int totalEntries;
  final bool needsZip64;
  _Eocd({
    required this.offset,
    required this.centralDirOffset,
    required this.centralDirSize,
    required this.totalEntries,
    required this.needsZip64,
  });
}

class _Zip64Eocd {
  final int centralDirOffset;
  final int centralDirSize;
  final int totalEntries;
  _Zip64Eocd({
    required this.centralDirOffset,
    required this.centralDirSize,
    required this.totalEntries,
  });
}
