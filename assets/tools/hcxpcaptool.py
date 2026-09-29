#!/usr/bin/env python3
"""
hcxpcaptool.py - Python alternative to hcxpcaptool for WPA handshake extraction.
Extracts WPA/WPA2 handshakes from pcap files and outputs hashcat format 22000.

Supports:
- Raw 802.11 frames (LINKTYPE_IEEE802_11 = 105)
- Radiotap headers (LINKTYPE_IEEE802_11_RADIO = 127)

Usage: hcxpcaptool.py --type=22000 <pcap_file>
Output: One hash per line in hashcat 22000 format.
"""

import sys
import struct
import os
import hashlib


def read_pcap(filename):
    """Read pcap file, yields (link_type, packet_data) tuples.
    link_type: 105 = 802.11, 127 = radiotap, 1 = Ethernet
    """
    try:
        with open(filename, 'rb') as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                return
            # Determine endianness from magic number
            magic_le = struct.unpack('<I', hdr[0:4])[0]
            if magic_le == 0xa1b2c3d4:
                endian = '<'
                magic = 0xa1b2c3d4
            elif magic_le == 0xd4c3b2a1:
                endian = '>'
                magic = 0xa1b2c3d4
            else:
                return
            # Read network/link type
            network = struct.unpack(endian + 'I', hdr[20:24])[0]
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break
                yield (network, pkt_data)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)


def strip_radiotap(packet):
    """Strip radiotap header, return 802.11 frame data."""
    if len(packet) < 4:
        return None
    # it_version(1), it_pad(1), it_len(2 LE)
    it_len = struct.unpack('<H', packet[2:4])[0]
    if it_len < 8 or it_len > len(packet):
        return None
    return packet[it_len:]


def parse_ieee80211(packet):
    """Parse 802.11 frame, return frame_ctrl, duration, addr1, addr2, addr3, seq, payload."""
    if len(packet) < 24:
        return None
    frame_ctrl = struct.unpack('<H', packet[0:2])[0]
    duration = struct.unpack('<H', packet[2:4])[0]
    addr1 = packet[4:10]
    addr2 = packet[10:16]
    addr3 = packet[16:22]
    seq = struct.unpack('<H', packet[22:24])[0]
    payload = packet[24:]
    return (frame_ctrl, duration, addr1, addr2, addr3, seq, payload)


def mac_str(mac_bytes):
    """Convert MAC bytes to lowercase hex string with colons."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def get_ssid_from_beacon(payload):
    """Extract SSID from beacon frame body."""
    if len(payload) < 12:
        return None
    # Fixed parameters: timestamp (8), beacon interval (2), capability info (2)
    offset = 12
    while offset < len(payload) - 2:
        tag_num = payload[offset]
        tag_len = payload[offset + 1]
        if offset + 2 + tag_len > len(payload):
            break
        if tag_num == 0:  # SSID tag
            return payload[offset + 2:offset + 2 + tag_len]
        offset += 2 + tag_len
    return None


def parse_eapol(payload):
    """Parse EAPOL key frame.
    Returns (key_info, replay_counter, nonce, iv, rsc, id, mic, key_data_len, key_data, raw_eapol_frame)
    raw_eapol_frame includes the full EAPOL packet (version + type + length + key_data)
    """
    # EAPOL header: version(1), type(1), length(2)
    if len(payload) < 4:
        return None
    eapol_version = payload[0]
    eapol_type = payload[1]
    if eapol_type != 3:  # EAPOL-Key
        return None
    eapol_len = struct.unpack('>H', payload[2:4])[0]
    key_data = payload[4:4 + eapol_len]
    if len(key_data) < 95:
        return None
    # EAPOL-Key frame (WPA2):
    # descriptor_type(1), key_info(2), key_len(2), replay_counter(8),
    # key_nonce(32), key_iv(16), key_rsc(8), key_id(8), key_mic(16),
    # key_data_len(2), key_data(variable)
    desc_type = key_data[0]
    key_info = struct.unpack('>H', key_data[1:3])[0]
    key_len = struct.unpack('>H', key_data[3:5])[0]
    replay_counter = key_data[5:13]
    key_nonce = key_data[13:45]  # 32 bytes ANonce or SNonce
    key_iv = key_data[45:61]    # 16 bytes
    key_rsc = key_data[61:69]   # 8 bytes
    key_id = key_data[69:77]    # 8 bytes
    key_mic = key_data[77:93]   # 16 bytes MIC
    key_data_len = struct.unpack('>H', key_data[93:95])[0]
    key_data_content = key_data[95:95 + key_data_len] if 95 + key_data_len <= len(key_data) else b''
    # Raw EAPOL frame (used for MIC calculation / hash output)
    raw_eapol = payload[:4 + eapol_len]
    return (key_info, replay_counter, key_nonce, key_iv, key_rsc, key_id, key_mic, key_data_len, key_data_content, raw_eapol)


def is_install_flag_set(key_info):
    return bool(key_info & 0x0040)


def is_ack_flag_set(key_info):
    return bool(key_info & 0x0080)


def is_mic_flag_set(key_info):
    return bool(key_info & 0x0100)


def is_secure_flag_set(key_info):
    return bool(key_info & 0x0002)


def extract_handshakes(pcap_file):
    """Extract WPA handshakes from a pcap file.
    Returns list of tuples: (ssid, mac_ap, mac_sta, anonce, snonce, mic, eapol_payload, msg_num)
    """
    handshakes = {}  # key: (mac_ap, mac_sta) -> dict of msg_num -> msg_info
    ssids = {}  # mac_ap -> ssid
    beacons_seen = 0
    data_seen = 0
    eapol_seen = 0

    for link_type, pkt in read_pcap(pcap_file):
        # Strip radiotap if needed
        if link_type == 127:  # radiotap
            frame_data = strip_radiotap(pkt)
            if frame_data is None:
                continue
        elif link_type == 105:  # raw 802.11
            frame_data = pkt
        else:
            continue

        frame = parse_ieee80211(frame_data)
        if frame is None:
            continue
        frame_ctrl, duration, addr1, addr2, addr3, seq, payload = frame

        # Frame type: 0x00 = Management, 0x04 = Control, 0x08 = Data
        frame_type = frame_ctrl & 0x000C
        frame_subtype = frame_ctrl & 0x00F0

        # Beacon frame (Management, subtype 8 = 0x0080)
        if frame_type == 0x00 and frame_subtype == 0x0080:
            beacons_seen += 1
            ssid = get_ssid_from_beacon(payload)
            if ssid and len(ssid) > 0:
                ssids[addr2] = ssid
            continue

        # Data frame (type 0x08)
        if frame_type != 0x08:
            continue

        data_seen += 1

        from_ds = bool(frame_ctrl & 0x0200)
        to_ds = bool(frame_ctrl & 0x0100)

        # Determine AP and STA MAC addresses
        if not from_ds and not to_ds:
            mac_ap = addr3
            mac_sta = addr2
        elif from_ds and not to_ds:
            mac_ap = addr2
            mac_sta = addr1
        elif not from_ds and to_ds:
            mac_ap = addr1
            mac_sta = addr2
        else:
            continue

        # Check for QoS data (subtype bit 7 set = 0x0080)
        # QoS data frames have an extra 2-byte QoS Control field
        is_qos = bool(frame_subtype & 0x0080)
        qos_offset = 2 if is_qos else 0
        header_len = 24 + qos_offset
        if len(frame_data) < header_len:
            continue

        payload = frame_data[header_len:]

        # Check LLC/SNAP
        if payload[0] != 0xAA or payload[1] != 0xAA or payload[2] != 0x03:
            continue

        # Check if it's 802.1X EAPOL
        ethertype = struct.unpack('>H', payload[6:8])[0]
        if ethertype != 0x888E:  # EAPOL
            continue

        eapol_payload = payload[8:]
        eapol = parse_eapol(eapol_payload)
        if eapol is None:
            continue

        eapol_seen += 1
        key_info, replay_counter, key_nonce, key_iv, key_rsc, key_id, key_mic, key_data_len, key_data_content, raw_eapol = eapol

        if not is_mic_flag_set(key_info):
            continue

        install = is_install_flag_set(key_info)
        ack = is_ack_flag_set(key_info)

        # Determine handshake message number
        # Msg 1: AP -> STA, Install=0, ACK=0, Secure=1, MIC=0 (ANonce from AP, no MIC)
        # Msg 2: STA -> AP, Install=0, ACK=0, Secure=?, MIC=1 (SNonce from STA, MIC present)
        # Msg 3: AP -> STA, Install=1, ACK=1, Secure=1, MIC=1 (GTK + ANonce)
        # Msg 4: STA -> AP, Install=0, ACK=1, Secure=1, MIC=1 (ACK)
        msg_num = 0
        has_mic = is_mic_flag_set(key_info)

        if not install and not ack and not has_mic:
            msg_num = 1  # AP->STA (Message 1, ANonce, no MIC)
        elif not install and not ack and has_mic:
            msg_num = 2  # STA->AP (Message 2, SNonce + MIC)
        elif install and ack and has_mic:
            msg_num = 3  # AP->STA (Message 3, GTK + ANonce + MIC)
        elif not install and ack and has_mic:
            msg_num = 4  # STA->AP (Message 4, ACK + MIC)

        if msg_num == 0:
            continue

        key_tuple = (bytes(mac_ap), bytes(mac_sta))
        if key_tuple not in handshakes:
            handshakes[key_tuple] = {}

        handshakes[key_tuple][msg_num] = {
            'replay': replay_counter,
            'nonce': key_nonce,
            'mic': key_mic,
            'eapol': raw_eapol,
            'key_data_len': key_data_len,
            'key_data': key_data_content,
        }

    return handshakes, ssids, beacons_seen, data_seen, eapol_seen


def build_hashcat_22000(ssid, mac_ap, mac_sta, anonce, eapol_msg2):
    """Build hashcat 22000 format hash string.
    Format: WPA*01*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
    Message pair "02" = message 1/2 pair (AP nonce + STA response)
    """
    mac_ap_hex = mac_ap.hex()
    mac_sta_hex = mac_sta.hex()
    essid_hex = ssid.hex()
    anonce_hex = anonce.hex()
    eapol_hex = eapol_msg2.hex()
    msg_pair = "02"
    hash_line = f"WPA*01*{mac_ap_hex}*{mac_sta_hex}*{essid_hex}*{anonce_hex}*{eapol_hex}*{msg_pair}"
    return hash_line


def main():
    if len(sys.argv) < 2:
        print("Usage: hcxpcaptool.py [--type=22000] <pcap_file>", file=sys.stderr)
        sys.exit(1)

    pcap_file = None
    hash_type = "22000"

    for arg in sys.argv[1:]:
        if arg.startswith("--type="):
            hash_type = arg.split("=", 1)[1]
        else:
            pcap_file = arg

    if not pcap_file or not os.path.exists(pcap_file):
        print(f"Error: pcap file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    handshakes, ssids, beacons, data_frames, eapol_count = extract_handshakes(pcap_file)

    if not handshakes:
        print("", file=sys.stderr)
        print(f"Debug: {beacons} beacons, {data_frames} data frames, {eapol_count} EAPOL", file=sys.stderr)
        print(f"Debug: SSIDs found: {len(ssids)}", file=sys.stderr)
        print("No WPA handshakes found", file=sys.stderr)
        sys.exit(1)

    output_count = 0
    for (mac_ap, mac_sta), msgs in handshakes.items():
        ssid = ssids.get(mac_ap, b'unknown')

        # Look for msg1 (ANonce) and msg2 (SNonce + MIC)
        if 1 in msgs and 2 in msgs:
            msg1 = msgs[1]
            msg2 = msgs[2]
            anonce = msg1['nonce']
            hash_line = build_hashcat_22000(
                ssid, mac_ap, mac_sta, anonce, msg2['eapol']
            )
            print(hash_line)
            output_count += 1
        # Also try msg2 + msg3 (msg3 also has ANonce)
        elif 2 in msgs and 3 in msgs:
            msg2 = msgs[2]
            msg3 = msgs[3]
            anonce = msg3['nonce']
            hash_line = build_hashcat_22000(
                ssid, mac_ap, mac_sta, anonce, msg2['eapol']
            )
            print(hash_line)
            output_count += 1

    if output_count == 0:
        print("", file=sys.stderr)
        print(f"Debug: {len(handshakes)} STA/AP pairs, but no complete msg1/msg2 or msg2/msg3 pairs", file=sys.stderr)
        for (mac_ap, mac_sta), msgs in handshakes.items():
            ssid = ssids.get(mac_ap, b'unknown')
            print(f"  {ssid.decode('utf-8', errors='replace')}: msgs={sorted(msgs.keys())}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
