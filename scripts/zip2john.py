#!/usr/bin/env python3
"""
zip2john.py — 从加密 ZIP 提取 hashcat 兼容哈希（简化版）
输出 PKZIP 格式 (hashcat -m 17200/17210/17220/17225/17230)

注意：这是简化实现，复杂 ZIP（分卷、ZIP64、AES-NI）建议用
JohnTheRipper 的 zip2john.exe（fetch_tools.ps1 可自动获取）。
"""
import struct
import sys
import binascii
import os

EOCD_SIG = b'\x50\x4b\x05\x06'
CD_SIG = b'\x50\x4b\x01\x02'
LFH_SIG = b'\x50\x4b\x03\x04'


def find_eocd(data):
    idx = data.rfind(EOCD_SIG)
    if idx < 0:
        return None
    return idx


def read_central_directory(data, eocd_off):
    (sig, disk, cd_disk, n_disk, n_ent, tot_ent,
     cd_size, cd_off, comm_len) = struct.unpack_from('<IHHHHIIIH', data, eocd_off)
    entries = []
    off = cd_off
    for _ in range(tot_ent):
        if data[off:off+4] != CD_SIG:
            break
        (csig, ver_made, ver_need, flag, method, mtime, mdate,
         crc, comp_size, uncomp_size, fn_len, ex_len, cm_len,
         disk_no, int_attr, ext_attr, lfh_off) = struct.unpack_from(
            '<IHHHHHHIIIHHHHHII', data, off)
        name = data[off+46:off+46+fn_len].decode('utf-8', 'replace')
        extra = data[off+46+fn_len:off+46+fn_len+ex_len]
        comment = data[off+46+fn_len+ex_len:off+46+fn_len+ex_len+cm_len]
        entries.append({
            'name': name, 'flag': flag, 'method': method,
            'crc': crc, 'comp_size': comp_size, 'uncomp_size': uncomp_size,
            'mtime': mtime, 'mdate': mdate, 'lfh_off': lfh_off,
            'extra': extra, 'comment': comment,
        })
        off += 46 + fn_len + ex_len + cm_len
    return entries


def read_local_header(data, lfh_off):
    (sig, ver, flag, method, mtime, mdate, crc,
     comp_size, uncomp_size, fn_len, ex_len) = struct.unpack_from(
        '<IHHHHHIIIHH', data, lfh_off)
    name_start = lfh_off + 30
    data_start = name_start + fn_len + ex_len
    return {
        'flag': flag, 'method': method, 'mtime': mtime, 'mdate': mdate,
        'crc': crc, 'comp_size': comp_size, 'uncomp_size': uncomp_size,
        'data_start': data_start,
    }


def extract_zip(path):
    with open(path, 'rb') as f:
        data = f.read()
    eocd = find_eocd(data)
    if eocd is None:
        sys.stderr.write('非 ZIP 文件\n')
        return None
    entries = read_central_directory(data, eocd)
    enc = [e for e in entries if e['flag'] & 0x1]
    if not enc:
        sys.stderr.write('ZIP 未加密\n')
        return None
    targets = [e for e in enc if e['comp_size'] > 0]
    if not targets:
        targets = enc[:1]
    out_parts = []
    for e in targets[:3]:
        lh = read_local_header(data, e['lfh_off'])
        ds = lh['data_start']
        check_byte_crc = (e['crc'] >> 24) & 0xff
        check_byte_time = (lh['mtime'] >> 8) & 0xff
        use_time = bool(e['flag'] & 0x8)
        check_byte = check_byte_time if use_time else check_byte_crc
        check_type = 2 if use_time else 1
        enc_header = data[ds:ds+12]
        comp_size = e['comp_size']
        data_len = min(comp_size, 16)
        extra_data = data[ds+12:ds+12+data_len] if comp_size > 12 else b''
        part = '$pkzip2$1*{ct}*2*0*{cs:x}*c*{eh}*{cs:x}*{dl:x}*{ed}*$/pkzip2$'.format(
            ct=check_type, cs=comp_size, eh=enc_header.hex(),
            dl=data_len, ed=extra_data.hex() if extra_data else '00')
        out_parts.append('{}_{}:{}'.format(
            os.path.basename(path), e['name'], part))
    if out_parts:
        return out_parts[0]
    return None


def main():
    if len(sys.argv) < 2:
        sys.stderr.write('用法: zip2john.py <zip文件>\n')
        sys.exit(1)
    result = extract_zip(sys.argv[1])
    if result:
        print(result)
    else:
        sys.exit(2)


if __name__ == '__main__':
    main()
