#!/usr/bin/env python3
"""Rebuild a re-signed APK from the CI-built intermediate APK.

Re-signing (apksigner, v2/v3 only) leaves every zip entry and the central
directory unchanged; it only replaces the APK Signing Block (plus alignment
padding before it) and moves the central directory offset in the EOCD record.
That replacement - signatures and public certificate only, no private key -
is stored next to this script, so CI can publish the signed APK without the
key or a 500 MB upload.

  extract: splice_signature.py extract <intermediate.apk> <signed.apk> <out.sigblock>
  apply:   splice_signature.py apply   <intermediate.apk> <in.sigblock>  <out.apk>
"""
import struct
import sys

MAGIC = b"APK Sig Block 42"


def layout(data):
    """Return (signing block start, central directory offset, EOCD offset)."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0:
        raise SystemExit("no end of central directory record")
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    if cd_off + cd_size != eocd:
        raise SystemExit("unexpected data between central directory and EOCD")
    if data[cd_off - 16:cd_off] != MAGIC:
        raise SystemExit("no APK Signing Block before the central directory")
    block_size = struct.unpack_from("<Q", data, cd_off - 24)[0]
    start = cd_off - (block_size + 8)
    if struct.unpack_from("<Q", data, start)[0] != block_size:
        raise SystemExit("APK Signing Block size fields disagree")
    return start, cd_off, eocd


def main():
    mode, a, b, out = sys.argv[1:5]
    base = open(a, "rb").read()
    start, cd_off, eocd = layout(base)
    if mode == "extract":
        signed = open(b, "rb").read()
        s_start, s_cd, s_eocd = layout(signed)
        if signed[:start] != base[:start]:
            raise SystemExit("zip entries differ, not just the signature")
        if signed[s_cd:s_eocd] != base[cd_off:eocd]:
            raise SystemExit("central directories differ")
        open(out, "wb").write(signed[start:s_cd])
    elif mode == "apply":
        insert = open(b, "rb").read()
        if insert[-16:] != MAGIC:
            raise SystemExit("signature block file does not end with the APK Sig Block magic")
        new_cd = start + len(insert)
        eocd_rec = bytearray(base[eocd:])
        struct.pack_into("<I", eocd_rec, 16, new_cd)
        open(out, "wb").write(base[:start] + insert + base[cd_off:eocd] + bytes(eocd_rec))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
