#!/usr/bin/env python3
"""
ZIP hash extractor for hashcat.
Based on zip2hashcat by oliverjueguen (MIT License).
Supports:
- WinZip AES -> $zip2$ format, hashcat mode 13600
- ZipCrypto -> $pkzip$ format, hashcat mode 17200/17210/17220/17225
"""
import sys
import struct
from pathlib import Path

LOCAL_FILE_HEADER_SIG = b"PK\x03\x04"
CENTRAL_DIR_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
ZIP64_EOCD_SIG = b"PK\x06\x06"
COMP_STORED = 0
COMP_AES = 99
FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008
AES_EXTRA_FIELD_ID = 0x9901
AES_PWD_VERIFY_SIZE = 2
AES_AUTH_CODE_SIZE = 10
AES_SALT_SIZE = {1: 8, 2: 12, 3: 16}
ZIP64_EXTRA_FIELD_ID = 0x0001
_ZIP64_SENTINEL_2 = 0xFFFF
_ZIP64_SENTINEL_4 = 0xFFFFFFFF
ZIP64_EOCD_LOC_SIG = b"PK\x06\x07"


class ZipEntry:
    def __init__(self, filename, compression_method, flags, crc32,
                 compressed_size, uncompressed_size, file_data_offset,
                 local_header_offset, mod_time, aes_strength=None,
                 aes_actual_compression=None):
        self.filename = filename
        self.compression_method = compression_method
        self.flags = flags
        self.crc32 = crc32
        self.compressed_size = compressed_size
        self.uncompressed_size = uncompressed_size
        self.file_data_offset = file_data_offset
        self.local_header_offset = local_header_offset
        self.mod_time = mod_time
        self.aes_strength = aes_strength
        self.aes_actual_compression = aes_actual_compression

    @property
    def is_encrypted(self):
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def is_aes(self):
        return self.compression_method == COMP_AES and self.aes_strength is not None

    @property
    def is_zipcrypto(self):
        return self.is_encrypted and not self.is_aes

    @property
    def is_compressed(self):
        if self.is_aes:
            return self.aes_actual_compression != COMP_STORED
        return self.compression_method != COMP_STORED

    @property
    def check4(self):
        if self.flags & FLAG_DATA_DESCRIPTOR:
            return format((self.mod_time >> 8) & 0xFF, "02x") + format(self.mod_time & 0xFF, "02x")
        return format((self.crc32 >> 24) & 0xFF, "02x") + format((self.crc32 >> 16) & 0xFF, "02x")

    @property
    def crc32_hex(self):
        return format(self.crc32, "08x")


def parse_aes_extra(extra_data):
    offset = 0
    while offset + 4 <= len(extra_data):
        header_id, data_size = struct.unpack_from("<HH", extra_data, offset)
        offset += 4
        if header_id == AES_EXTRA_FIELD_ID and data_size >= 7:
            _ver, _vendor, strength, actual_comp = struct.unpack_from(
                "<HHBh", extra_data, offset)
            return strength, actual_comp
        offset += data_size
    return None, None


def parse_zip64_extra(extra_data, need_uncomp, need_comp, need_offset):
    offset = 0
    while offset + 4 <= len(extra_data):
        header_id, data_size = struct.unpack_from("<HH", extra_data, offset)
        offset += 4
        if header_id == ZIP64_EXTRA_FIELD_ID:
            field_offset = offset
            uncomp, comp, lh_offset = 0, 0, 0
            if need_uncomp and field_offset + 8 <= offset + data_size:
                uncomp = struct.unpack_from("<Q", extra_data, field_offset)[0]
                field_offset += 8
            if need_comp and field_offset + 8 <= offset + data_size:
                comp = struct.unpack_from("<Q", extra_data, field_offset)[0]
                field_offset += 8
            if need_offset and field_offset + 8 <= offset + data_size:
                lh_offset = struct.unpack_from("<Q", extra_data, field_offset)[0]
            return uncomp, comp, lh_offset
        offset += data_size
    return 0, 0, 0


def parse_zip(data):
    eocd_pos = data.rfind(EOCD_SIG)
    if eocd_pos == -1:
        raise ValueError("Not a valid ZIP file (no EOCD record found)")
    (_disk_num, _disk_cd, _entries_on_disk, total_entries,
     _cd_size, cd_offset, _comment_len) = struct.unpack_from(
        "<HHHHIIH", data, eocd_pos + 4)
    if total_entries == _ZIP64_SENTINEL_2 or cd_offset == _ZIP64_SENTINEL_4:
        # Find ZIP64 EOCD locator
        zip64_loc_pos = data.rfind(ZIP64_EOCD_LOC_SIG)
        if zip64_loc_pos != -1 and zip64_loc_pos + 20 <= len(data):
            (_sig, _disk_num, zip64_eocd_offset, _total_disks) = struct.unpack_from(
                "<IIQI", data, zip64_loc_pos)
            if zip64_eocd_offset + 56 <= len(data):
                # ZIP64 EOCD: sig(4) + size(8) + ver_made(2) + ver_needed(2) +
                # disk_num(4) + disk_cd(4) + entries_on_disk(8) + total_entries(8) +
                # cd_size(8) + cd_offset(8)
                (_sig2, _z64_size, _ver_made, _ver_needed, _z64_disk, _z64_disk_cd,
                 z64_entries_disk, z64_total, z64_cd_size, z64_cd_offset) = struct.unpack_from(
                    "<IQHHIIQQQQ", data, zip64_eocd_offset)
                total_entries = z64_total
                cd_offset = z64_cd_offset
    entries = []
    pos = cd_offset
    for _ in range(total_entries):
        if pos + 46 > len(data) or data[pos:pos + 4] != CENTRAL_DIR_SIG:
            break
        (_ver_made, _ver_needed, flags, compression, mod_time, _mod_date,
         crc32, comp_size, uncomp_size, fname_len, extra_len, comment_len,
         _disk_start, _int_attr, _ext_attr, local_header_offset) = struct.unpack_from(
            "<HHHHHHIIIHHHHHII", data, pos + 4)
        filename = data[pos + 46:pos + 46 + fname_len].decode("utf-8", errors="replace")
        extra_data = data[pos + 46 + fname_len:pos + 46 + fname_len + extra_len]
        need_uncomp = uncomp_size == _ZIP64_SENTINEL_4
        need_comp = comp_size == _ZIP64_SENTINEL_4
        need_offset = local_header_offset == _ZIP64_SENTINEL_4
        if need_uncomp or need_comp or need_offset:
            z64_uncomp, z64_comp, z64_offset = parse_zip64_extra(
                extra_data, need_uncomp, need_comp, need_offset)
            if need_uncomp:
                uncomp_size = z64_uncomp
            if need_comp:
                comp_size = z64_comp
            if need_offset:
                local_header_offset = z64_offset
        aes_strength, aes_actual_comp = parse_aes_extra(extra_data)
        file_data_offset = 0
        if local_header_offset + 30 <= len(data):
            if data[local_header_offset:local_header_offset + 4] == LOCAL_FILE_HEADER_SIG:
                lf_len, le_len = struct.unpack_from("<HH", data, local_header_offset + 26)
                file_data_offset = local_header_offset + 30 + lf_len + le_len
        entries.append(ZipEntry(
            filename=filename, compression_method=compression, flags=flags,
            crc32=crc32, compressed_size=comp_size, uncompressed_size=uncomp_size,
            file_data_offset=file_data_offset, local_header_offset=local_header_offset,
            mod_time=mod_time, aes_strength=aes_strength,
            aes_actual_compression=aes_actual_comp))
        pos += 46 + fname_len + extra_len + comment_len
    return entries


def extract_zipcrypto_hash(data, entries):
    # hashcat MAX_DATA limit is 327680 bytes (~320KB)
    MAX_DATA = 327680
    # Sort by compressed_size, use smallest entry that fits
    sorted_entries = sorted(entries, key=lambda e: e.compressed_size)
    # Use only the smallest entry (single-file mode)
    entry = sorted_entries[0]
    if entry.compressed_size > MAX_DATA:
        encrypted = data[entry.file_data_offset:entry.file_data_offset + MAX_DATA]
        actual_len = MAX_DATA
    else:
        encrypted = data[entry.file_data_offset:entry.file_data_offset + entry.compressed_size]
        actual_len = len(encrypted)
    if actual_len < 12:
        raise ValueError("Encrypted data too small")
    dt = 2  # data_type_enum=2 means full data with CL/UL/CR/OF/OX
    ox = entry.file_data_offset - entry.local_header_offset
    # hashcat 7.1.2 uses $pkzip2$ format with check_type=1
    # Format: $pkzip2$<count>*<cs_size>*<dt>*<mt>*<CL>*<UL>*<CR>*<OF>*<OX>*<CT>*<DL>*<CS>*<DA>*$/pkzip2$
    hash_str = (
        f"$pkzip2$1*1*"
        f"{dt}*0"
        f"*{entry.compressed_size:x}*{entry.uncompressed_size:x}"
        f"*{entry.crc32_hex}*{entry.local_header_offset:x}*{ox:x}"
        f"*{entry.compression_method:x}"
        f"*{actual_len:x}"
        f"*{entry.check4}"
        f"*{encrypted.hex()}"
        f"*$/pkzip2$"
    )
    # Return mode based on compression
    mode = 17200 if entry.is_compressed else 17210
    return hash_str, mode


def extract_aes_hash(data, entries):
    """提取 WinZip AES 哈希 (hashcat -m 13600)。

    $zip2$ 字段结构（* 分隔）：
      [0] 保留       [1] AES 强度(1/2/3)   [2] 保留
      [3] salt       [4] 密码校验字节(2B)  [5] 数据长度(hex)
      [6] 加密数据   [7] 认证码(10B)

    注意：字段 [6] 的加密数据段必须真实输出。早期版本这里被写成空串，
    导致 hashcat 拿不到密文无法校验密码，所有 AES-ZIP 都破解失败。
    """
    entry = min(entries, key=lambda e: e.compressed_size)
    salt_size = AES_SALT_SIZE.get(entry.aes_strength, 16)
    off = entry.file_data_offset
    salt = data[off:off + salt_size]
    pwd_verify = data[off + salt_size:off + salt_size + AES_PWD_VERIFY_SIZE]
    auth_off = off + entry.compressed_size - AES_AUTH_CODE_SIZE
    auth_code = data[auth_off:auth_off + AES_AUTH_CODE_SIZE]
    payload_start = off + salt_size + AES_PWD_VERIFY_SIZE
    payload = data[payload_start:auth_off]
    payload_len = len(payload)
    if payload_len < 0:
        raise ValueError("AES 加密数据结构异常：认证码位置早于数据起始位置")
    return (
        f"$zip2$*0*{entry.aes_strength}*0"
        f"*{salt.hex()}*{pwd_verify.hex()}"
        f"*{payload_len:x}*{payload.hex()}*{auth_code.hex()}"
        f"*$/zip2$"
    )


def extract_hash(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    entries = parse_zip(data)
    encrypted = [e for e in entries if e.is_encrypted]
    if not encrypted:
        raise ValueError("ZIP file is not password-protected")
    has_aes = all(e.is_aes for e in encrypted)
    has_zipcrypto = all(e.is_zipcrypto for e in encrypted)
    if has_aes:
        return extract_aes_hash(data, encrypted), 13600
    elif has_zipcrypto or (not has_aes):
        zc = [e for e in encrypted if e.is_zipcrypto]
        if not zc:
            zc = encrypted
        return extract_zipcrypto_hash(data, zc)
    else:
        raise ValueError("Unsupported encryption")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: zip2john.py <zipfile>", file=sys.stderr)
        sys.exit(1)
    try:
        hash_str, mode = extract_hash(sys.argv[1])
        print(hash_str)
        print("HASHCAT_MODE:%d" % mode, file=sys.stderr)
    except Exception as e:
        import traceback
        print("Error: %s" % e, file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
