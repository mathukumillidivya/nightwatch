"""Code enrichment of opaque log values, the way a SIEM decodes them before an analyst looks.

Windows logs many facts as GUIDs, bit masks and numbers: "Properties={1131f6aa-...}" is a request for directory
replication rights, "GrantedAccess=0x1010" on lsass.exe is a request to read its memory. These are lookups from
Microsoft's published documentation, not judgements, so code adds them. The decoded meaning is shown after the
value in ⟦ ⟧ and is never part of the evidence: quotes are checked against the raw fields only.
"""
from __future__ import annotations

import re

# Active Directory control access rights and schema classes (Microsoft [MS-ADTS] / schema documentation)
GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes (directory replication right)",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All (directory replication right, includes secrets)",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set (directory replication right)",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password (reset password right)",
    "19195a5b-6da0-11d0-afd3-00c04fd930c9": "object class domainDNS (the domain root object)",
    "bf967aba-0de6-11d0-a285-00aa003049e2": "object class user",
    "bf967a86-0de6-11d0-a285-00aa003049e2": "object class computer",
    "bf967a9c-0de6-11d0-a285-00aa003049e2": "object class group",
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1": "object class groupPolicyContainer",
    "bf967a0a-0de6-11d0-a285-00aa003049e2": "attribute pwdLastSet",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "attribute servicePrincipalName",
}
# Directory object access mask bits (event 4662 / 5136)
DS_MASK = {0x1: "create child", 0x2: "delete child", 0x4: "list contents", 0x8: "self write", 0x10: "read property",
           0x20: "write property", 0x100: "control access (extended right)", 0x10000: "delete",
           0x20000: "read permissions", 0x40000: "WRITE_DAC (change permissions)", 0x80000: "WRITE_OWNER (take ownership)"}
# Process access rights (Sysmon 10 GrantedAccess)
PROC_MASK = {0x1: "terminate", 0x2: "create thread", 0x8: "VM operation", 0x10: "VM read (read memory)",
             0x20: "VM write (write memory)", 0x40: "duplicate handle", 0x400: "query information",
             0x1000: "query limited information", 0x100000: "synchronize"}
LOGON = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock", "8": "network cleartext",
         "9": "new credentials (runas /netonly)", "10": "remote interactive (RDP)", "11": "cached interactive"}
TICKET = {"0x17": "RC4 (weak, typical of Kerberoasting)", "0x18": "RC4-EXP", "0x12": "AES256", "0x11": "AES128", "0x3": "DES"}

GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _bits(value: str, table: dict[int, str]) -> str | None:
    try:
        v = int(value, 16)
    except ValueError:
        return None
    if v in (0x1fffff, 0x1f3fff, 0x1fffffff):
        return "full access (all rights)"
    names = [n for bit, n in table.items() if v & bit]
    return ", ".join(names) if names else None


def annotate(channel: str, event_id: int, fields: dict) -> dict[str, str]:
    """Field name -> decoded meaning, for the fields this module understands."""
    out = {}
    for k, v in fields.items():
        v = str(v)
        if k in ("Properties", "ObjectType", "ObjectName", "AttributeLDAPDisplayName"):
            hits = [GUIDS[g.lower()] for g in GUID.findall(v) if g.lower() in GUIDS]
            if hits:
                out[k] = "; ".join(dict.fromkeys(hits))
        if k == "AccessMask" and event_id in (4662, 5136):
            d = _bits(v, DS_MASK)
            if d:
                out[k] = d
        if k == "GrantedAccess" and channel == "Sysmon":
            d = _bits(v, PROC_MASK)
            if d:
                out[k] = d
        if k == "LogonType" and v in LOGON:
            out[k] = LOGON[v]
        if k == "TicketEncryptionType" and v.lower() in TICKET:
            out[k] = TICKET[v.lower()]
    return out
