import struct
import sys

pcap = sys.argv[1]

with open(pcap, 'rb') as f:
    hdr = f.read(24)
    network = struct.unpack('<I', hdr[20:24])[0]
    print('Link type:', network)
    count = 0
    while count < 30:
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)
        pkt = f.read(incl_len)
        if len(pkt) < incl_len:
            break

        if network == 127:
            it_len = struct.unpack('<H', pkt[2:4])[0]
            frame = pkt[it_len:]
        else:
            frame = pkt

        if len(frame) < 24:
            print(f'  Short frame: {len(frame)} bytes')
            count += 1
            continue

        fc = struct.unpack('<H', frame[0:2])[0]
        ftype = fc & 0x000C
        fsub = fc & 0x00F0

        if ftype == 8:
            from_ds = bool(fc & 0x0200)
            to_ds = bool(fc & 0x0100)
            is_qos = bool(fsub & 0x0080)

            hdr_len = 26 if is_qos else 24
            payload = frame[hdr_len:]

            if len(payload) >= 8 and payload[0] == 0xAA and payload[1] == 0xAA and payload[2] == 0x03:
                ethertype = struct.unpack('>H', payload[6:8])[0]
                print(f'  Data sub=0x{fsub:02x} qos={is_qos} fromDS={from_ds} toDS={to_ds}: len={incl_len}, ethertype=0x{ethertype:04x}')
                if ethertype == 0x888E:
                    eapol_ver = payload[8]
                    eapol_type = payload[9]
                    eapol_len = struct.unpack('>H', payload[10:12])[0]
                    print(f'    EAPOL: ver={eapol_ver} type={eapol_type} len={eapol_len}')
            else:
                first_bytes = payload[:min(12, len(payload))].hex()
                print(f'  Data sub=0x{fsub:02x} qos={is_qos} len={incl_len}: no LLC/SNAP, first={first_bytes}')

        elif ftype == 0:
            sub_name = hex(fsub)
            if fsub == 0x0080:
                sub_name = 'Beacon'
            elif fsub == 0x0040:
                sub_name = 'ProbeReq'
            elif fsub == 0x0050:
                sub_name = 'ProbeResp'
            elif fsub == 0x00B0:
                sub_name = 'Auth'
            elif fsub == 0x00C0:
                sub_name = 'Deauth'
            elif fsub == 0x0000:
                sub_name = 'AssocReq'
            elif fsub == 0x0010:
                sub_name = 'AssocResp'
            elif fsub == 0x00D0:
                sub_name = 'Action'
            print(f'  Mgmt {sub_name}: len={incl_len}')

        elif ftype == 4:
            sub_name = hex(fsub)
            if fsub == 0x00B0:
                sub_name = 'RTS'
            elif fsub == 0x00C0:
                sub_name = 'CTS'
            elif fsub == 0x00D0:
                sub_name = 'ACK'
            elif fsub == 0x00A0:
                sub_name = 'PS-Poll'
            elif fsub == 0x00E0:
                sub_name = 'CF-End'
            print(f'  Ctrl {sub_name}: len={incl_len}')

        else:
            print(f'  Type=0x{ftype:02x} Sub=0x{fsub:02x}: len={incl_len}')

        count += 1
