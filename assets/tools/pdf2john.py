#!/usr/bin/env python3
"""
Self-contained PDF hash extractor - no external dependencies.
Supports PDF encryption revisions 2-6 (RC4 40/128-bit, AES 128/256-bit).
Outputs hashcat-compatible $pdf$ format.
"""
import sys
import re
import os


def _hex_to_bytes(hex_str):
    """Convert hex string to bytes, removing whitespace."""
    cleaned = re.sub(r'[\s\r\n]', '', hex_str)
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _parse_literal_string(s):
    """Parse a PDF literal string (inside parentheses), handling escapes."""
    result = bytearray()
    i = 0
    while i < len(s):
        c = s[i:i+1]
        if c == b'\\' and i + 1 < len(s):
            nxt = s[i+1:i+2]
            if nxt == b'n':
                result.append(ord('\n'))
                i += 2
            elif nxt == b'r':
                result.append(ord('\r'))
                i += 2
            elif nxt == b't':
                result.append(ord('\t'))
                i += 2
            elif nxt == b'b':
                result.append(8)
                i += 2
            elif nxt == b'f':
                result.append(12)
                i += 2
            elif nxt in (b'(', b')', b'\\'):
                result.append(ord(nxt))
                i += 2
            elif nxt in b'01234567':
                # Octal escape (up to 3 digits)
                oct_str = b''
                j = i + 1
                while j < len(s) and j < i + 4 and s[j:j+1] in b'01234567':
                    oct_str += s[j:j+1]
                    j += 1
                result.append(int(oct_str, 8))
                i = j
            else:
                result.append(ord(nxt))
                i += 2
        else:
            result.append(ord(c))
            i += 1
    return bytes(result)


def _get_string_value(raw):
    """Extract raw bytes from a PDF string value (hex <...> or literal (...))."""
    raw = raw.strip()
    if raw.startswith(b'<') and raw.endswith(b'>'):
        return _hex_to_bytes(raw[1:-1].decode('latin-1'))
    if raw.startswith(b'(') and raw.endswith(b')'):
        # Find matching closing paren
        depth = 0
        content = bytearray()
        i = 1
        while i < len(raw):
            if raw[i:i+1] == b'\\':
                content.append(raw[i])
                content.append(raw[i+1])
                i += 2
                continue
            if raw[i:i+1] == b'(':
                depth += 1
                content.append(raw[i])
                i += 1
            elif raw[i:i+1] == b')':
                if depth == 0:
                    break
                depth -= 1
                content.append(raw[i])
                i += 1
            else:
                content.append(raw[i])
                i += 1
        return _parse_literal_string(bytes(content))
    return None


def _get_int(raw):
    """Extract integer from PDF value bytes."""
    raw = raw.strip()
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _find_encryption_obj(data):
    """Find the encryption object number from the trailer."""
    # Search for /Encrypt N G R in trailer
    trailer_pos = data.rfind(b'trailer')
    if trailer_pos < 0:
        # Try xref + trailer
        trailer_pos = data.rfind(b'\\trailer')
    if trailer_pos < 0:
        return None, None

    # Look for /Encrypt in trailer area (last 8KB of file)
    search_area = data[max(0, len(data) - 16384):]
    m = re.search(rb'/Encrypt\s+(\d+)\s+(\d+)\s+R', search_area)
    if not m:
        return None, None
    return int(m.group(1)), int(m.group(2))


def _extract_object(data, obj_num, gen_num=0):
    """Extract the raw content of a PDF object (between 'obj' and 'endobj')."""
    marker = ('%d %d obj' % (obj_num, gen_num)).encode('latin-1')
    idx = data.find(marker)
    if idx < 0:
        # Try with different spacing
        for pattern in [b'%d %d obj ', b'%d %d obj\n', b'%d %d obj\r\n']:
            marker2 = pattern % (obj_num, gen_num)
            idx = data.find(marker2)
            if idx >= 0:
                break
    if idx < 0:
        return None

    # Find start of content (skip "N G obj" + whitespace)
    start = idx + len(marker)
    while start < len(data) and data[start:start+1] in (b' ', b'\n', b'\r', b'\t'):
        start += 1

    # Find endobj
    end = data.find(b'endobj', start)
    if end < 0:
        return None

    return data[start:end].strip()


def _extract_dict_field(obj_data, field_name):
    """Extract a field value from a PDF dictionary using regex.
    Returns raw bytes of the value, or None if not found.
    """
    pattern = ('/' + field_name + r'\s+').encode('latin-1')
    m = re.search(pattern, obj_data)
    if not m:
        return None

    pos = m.end()
    # Skip whitespace
    while pos < len(obj_data) and obj_data[pos:pos+1] in (b' ', b'\n', b'\r', b'\t'):
        pos += 1

    if pos >= len(obj_data):
        return None

    # Determine value type
    if obj_data[pos:pos+2] == b'<<':
        # Nested dictionary - find matching >>
        depth = 0
        end = pos
        while end < len(obj_data):
            if obj_data[end:end+2] == b'<<':
                depth += 1
                end += 2
            elif obj_data[end:end+2] == b'>>':
                depth -= 1
                if depth == 0:
                    end += 2
                    break
                end += 2
            else:
                end += 1
        return obj_data[pos:end]
    elif obj_data[pos:pos+1] == b'[':
        # Array
        depth = 0
        end = pos
        while end < len(obj_data):
            if obj_data[end:end+1] == b'[':
                depth += 1
                end += 1
            elif obj_data[end:end+1] == b']':
                depth -= 1
                if depth == 0:
                    end += 1
                    break
                end += 1
            else:
                end += 1
        return obj_data[pos:end]
    elif obj_data[pos:pos+1] == b'(':
        # Literal string - find matching )
        end = pos + 1
        while end < len(obj_data):
            if obj_data[end:end+1] == b'\\':
                end += 2
                continue
            if obj_data[end:end+1] == b')':
                end += 1
                break
            end += 1
        return obj_data[pos:end]
    elif obj_data[pos:pos+1] == b'<':
        # Hex string or dict
        if pos + 1 < len(obj_data) and obj_data[pos+1:pos+2] == b'<':
            # Dictionary <<...>>
            depth = 0
            end = pos
            while end < len(obj_data):
                if obj_data[end:end+2] == b'<<':
                    depth += 1
                    end += 2
                elif obj_data[end:end+2] == b'>>':
                    depth -= 1
                    if depth == 0:
                        end += 2
                        break
                    end += 2
                else:
                    end += 1
            return obj_data[pos:end]
        else:
            # Hex string <...>
            end = obj_data.find(b'>', pos + 1)
            if end < 0:
                return None
            return obj_data[pos:end+1]
    elif obj_data[pos:pos+1] == b'/':
        # Name - starts with /, read until next whitespace or delimiter
        end = pos + 1  # skip the leading /
        while end < len(obj_data) and obj_data[end:end+1] not in (b' ', b'\n', b'\r', b'\t', b'/', b'>', b']', b'['):
            end += 1
        return obj_data[pos:end]
    else:
        # Number or other simple value
        end = pos
        while end < len(obj_data) and obj_data[end:end+1] not in (b' ', b'\n', b'\r', b'\t', b'/', b'>', b']'):
            if obj_data[end:end+2] == b'>>':
                break
            end += 1
        return obj_data[pos:end]


def extract_pdf_hash(pdf_path):
    try:
        with open(pdf_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1

    # Find encryption object reference
    enc_obj_num, enc_gen_num = _find_encryption_obj(data)
    if enc_obj_num is None:
        print("Error: PDF is not encrypted (no /Encrypt in trailer)", file=sys.stderr)
        return 1

    # Extract encryption dictionary
    enc_obj = _extract_object(data, enc_obj_num, enc_gen_num)
    if enc_obj is None:
        print("Error: Cannot find encryption object %d %d R" % (enc_obj_num, enc_gen_num), file=sys.stderr)
        return 1

    # Extract fields
    filter_raw = _extract_dict_field(enc_obj, 'Filter')
    if filter_raw is None:
        print("Error: No /Filter in encryption dictionary", file=sys.stderr)
        return 1
    filter_str = filter_raw.decode('latin-1', errors='replace').strip().lstrip('/')

    if filter_str != 'Standard':
        print("Error: Unsupported encryption filter: %s" % filter_str, file=sys.stderr)
        return 1

    # V = algorithm version
    v_raw = _extract_dict_field(enc_obj, 'V')
    v = _get_int(v_raw) if v_raw else 1

    # R = revision
    r_raw = _extract_dict_field(enc_obj, 'R')
    r = _get_int(r_raw) if r_raw else 2

    # Length = key length in bits
    length_raw = _extract_dict_field(enc_obj, 'Length')
    key_bits = _get_int(length_raw) if length_raw else 40

    # P = permissions (signed 32-bit)
    p_raw = _extract_dict_field(enc_obj, 'P')
    p = _get_int(p_raw) if p_raw else 0
    if p is not None and p > 0x7FFFFFFF:
        p = p - 0x100000000

    # O = owner password hash
    o_raw = _extract_dict_field(enc_obj, 'O')
    o_bytes = _get_string_value(o_raw) if o_raw else None
    if o_bytes is None:
        print("Error: Cannot read /O value", file=sys.stderr)
        return 1

    # U = user password hash
    u_raw = _extract_dict_field(enc_obj, 'U')
    u_bytes = _get_string_value(u_raw) if u_raw else None
    if u_bytes is None:
        print("Error: Cannot read /U value", file=sys.stderr)
        return 1

    fname = os.path.basename(pdf_path)

    # Determine output format based on revision
    if r >= 5:
        # AES-256 (R5/R6)
        oe_raw = _extract_dict_field(enc_obj, 'OE')
        ue_raw = _extract_dict_field(enc_obj, 'UE')
        perms_raw = _extract_dict_field(enc_obj, 'Perms')

        oe_bytes = _get_string_value(oe_raw) if oe_raw else b''
        ue_bytes = _get_string_value(ue_raw) if ue_raw else b''
        perms_bytes = _get_string_value(perms_raw) if perms_raw else b''

        # hashcat format for mode 10700:
        # $pdf$5*6*256*<P>*1*<O_len>*<O>*<U_len>*<U>*<OE_len>*<OE>*<UE_len>*<UE>*16*<Perms>
        o_hex = o_bytes.hex()
        u_hex = u_bytes.hex()
        oe_hex = oe_bytes.hex()
        ue_hex = ue_bytes.hex()
        perms_hex = perms_bytes.hex()

        hash_line = "%s:$pdf$5*%d*%d*%d*1*%d*%s*%d*%s*%d*%s*%d*%s*%d*%s" % (
            fname, r, key_bits, p,
            len(o_bytes), o_hex,
            len(u_bytes), u_hex,
            len(oe_bytes), oe_hex,
            len(ue_bytes), ue_hex,
            len(perms_bytes), perms_hex)
    else:
        # RC4 (R2/R3) or AES-128 (R4)
        # hashcat format for modes 10400/10500/10600:
        # $pdf$<V>*<R>*<Length>*<P>*1*<O_len>*<O>*<U_len>*<U>
        o_hex = o_bytes.hex()
        u_hex = u_bytes.hex()

        hash_line = "%s:$pdf$%d*%d*%d*%d*1*%d*%s*%d*%s" % (
            fname, v, r, key_bits, p,
            len(o_bytes), o_hex,
            len(u_bytes), u_hex)

    print(hash_line)
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: pdf2john.py <pdffile>", file=sys.stderr)
        sys.exit(1)
    sys.exit(extract_pdf_hash(sys.argv[1]))
