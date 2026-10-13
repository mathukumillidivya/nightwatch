"""Turn a raw Windows event recording (thousands of Sysmon, Security and PowerShell events) into what an analyst reads.

A recording holds up to about 80,000 events (3,700 is typical), almost all of them normal background activity. The model never
sees the raw stream. Code does the reduction:

1. Every event is reduced to the fields that matter for its type and rendered as one line.
2. Variable parts (GUIDs, process ids, hex, random names) are masked to give the event's *template*. Repeated
   templates collapse into one line with a count.
3. Each template gets a score: how interesting its event type is, how rare the template is across the whole
   fleet of recordings (a template seen on most hosts is background), and how bursty it is within the recording.
4. The top templates form the *triage view* the agents start from. The wider *index* (every template of a
   non-ignored type) stays available to the agents through a search tool.

No labels are used anywhere in this file. Rarity comes from counting templates across recordings, the way a
SIEM learns a fleet baseline.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

CHANNELS = {
    "microsoft-windows-sysmon/operational": "Sysmon",
    "security": "Security",
    "microsoft-windows-powershell/operational": "PowerShell",
    "windows powershell": "PowerShell-classic",
    "system": "System",
    "microsoft-windows-wmi-activity/operational": "WMI",
    "microsoft-windows-taskscheduler/operational": "TaskScheduler",
    "microsoft-windows-windows firewall with advanced security/firewall": "Firewall",
    "microsoft-windows-bits-client/operational": "BITS",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "RDP-LSM",
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": "RDP-RCM",
    "directory service": "DirectoryService",
    "application": "Application",
}

# (channel, event id) -> (label, fields to keep, interest weight). Weight 0 = never shown.
S, SEC, PS = "Sysmon", "Security", "PowerShell"
TYPES: dict[tuple[str, int], tuple[str, list[str], float]] = {
    (S, 1): ("process created", ["User", "IntegrityLevel", "ParentImage", "Image", "CommandLine"], 3),
    (S, 2): ("file time changed", ["Image", "TargetFilename"], 2),
    (S, 3): ("network connection", ["Image", "User", "Initiated", "DestinationIp", "DestinationHostname", "DestinationPort"], 2),
    (S, 5): ("process ended", ["Image"], 0.3),
    (S, 6): ("driver loaded", ["ImageLoaded", "Signed", "Signature"], 3),
    (S, 7): ("image loaded", ["Image", "ImageLoaded", "Signed"], 0.6),
    (S, 8): ("remote thread created", ["SourceImage", "TargetImage", "StartModule", "StartFunction"], 3),
    (S, 9): ("raw disk read", ["Image", "Device"], 2),
    (S, 10): ("process accessed", ["SourceImage", "TargetImage", "GrantedAccess"], 1.5),
    (S, 11): ("file created", ["Image", "TargetFilename"], 2),
    (S, 12): ("registry key created/deleted", ["EventType", "Image", "TargetObject"], 1.2),
    (S, 13): ("registry value set", ["Image", "TargetObject", "Details"], 2),
    (S, 14): ("registry renamed", ["Image", "TargetObject", "NewName"], 2),
    (S, 15): ("alternate data stream", ["Image", "TargetFilename", "Contents"], 3),
    (S, 17): ("pipe created", ["Image", "PipeName"], 2),
    (S, 18): ("pipe connected", ["Image", "PipeName"], 2),
    (S, 19): ("WMI filter registered", ["Operation", "User", "Name", "Query"], 3),
    (S, 20): ("WMI consumer registered", ["Operation", "User", "Name", "Type", "Destination"], 3),
    (S, 21): ("WMI binding registered", ["Operation", "User", "Consumer", "Filter"], 3),
    (S, 22): ("DNS query", ["Image", "QueryName"], 1.5),
    (S, 23): ("file deleted", ["Image", "TargetFilename"], 1.5),
    (S, 25): ("process tampering", ["Image", "Type"], 3),
    (S, 26): ("file deleted", ["Image", "TargetFilename"], 1.5),
    (S, 28): ("file block shredding", ["Image", "TargetFilename"], 2),
    (SEC, 1102): ("audit log cleared", ["SubjectUserName"], 3),
    (SEC, 4624): ("logon", ["LogonType", "TargetUserName", "TargetDomainName", "IpAddress", "AuthenticationPackageName", "ProcessName"], 1.5),
    (SEC, 4625): ("failed logon", ["LogonType", "TargetUserName", "IpAddress", "Status", "ProcessName"], 2),
    (SEC, 4648): ("logon with explicit credentials", ["SubjectUserName", "TargetUserName", "TargetServerName", "ProcessName"], 2.5),
    (SEC, 4656): ("handle requested", ["SubjectUserName", "ProcessName", "ObjectType", "ObjectName", "AccessMask"], 1),
    (SEC, 4657): ("registry value modified", ["SubjectUserName", "ProcessName", "ObjectName", "ObjectValueName", "NewValue"], 2.5),
    (SEC, 4661): ("SAM/directory handle requested", ["SubjectUserName", "ProcessName", "ObjectType", "ObjectName", "AccessMask"], 2),
    (SEC, 4662): ("directory object operation", ["SubjectUserName", "ObjectType", "ObjectName", "AccessMask", "Properties"], 2),
    (SEC, 4663): ("object accessed", ["SubjectUserName", "ProcessName", "ObjectType", "ObjectName", "AccessMask"], 1),
    (SEC, 4670): ("object permissions changed", ["SubjectUserName", "ProcessName", "ObjectType", "ObjectName"], 1.5),
    (SEC, 4672): ("special privileges at logon", ["SubjectUserName", "PrivilegeList"], 0.5),
    (SEC, 4673): ("privileged service called", ["SubjectUserName", "ProcessName", "Service", "PrivilegeList"], 1),
    (SEC, 4674): ("privileged object operation", ["SubjectUserName", "ProcessName", "ObjectName", "PrivilegeList"], 1),
    (SEC, 4688): ("process created", ["SubjectUserName", "ParentProcessName", "NewProcessName", "CommandLine"], 3),
    (SEC, 4697): ("service installed", ["SubjectUserName", "ServiceName", "ServiceFileName", "ServiceStartType"], 3),
    (SEC, 4698): ("scheduled task created", ["SubjectUserName", "TaskName", "TaskContent"], 3),
    (SEC, 4699): ("scheduled task deleted", ["SubjectUserName", "TaskName"], 2.5),
    (SEC, 4700): ("scheduled task enabled", ["SubjectUserName", "TaskName"], 2),
    (SEC, 4702): ("scheduled task updated", ["SubjectUserName", "TaskName", "TaskContentNew"], 1.5),
    (SEC, 4719): ("audit policy changed", ["SubjectUserName", "CategoryId", "SubcategoryGuid", "AuditPolicyChanges"], 3),
    (SEC, 4720): ("user account created", ["SubjectUserName", "TargetUserName"], 3),
    (SEC, 4722): ("user account enabled", ["SubjectUserName", "TargetUserName"], 2.5),
    (SEC, 4724): ("password reset", ["SubjectUserName", "TargetUserName"], 2.5),
    (SEC, 4728): ("member added to global group", ["SubjectUserName", "MemberName", "TargetUserName"], 3),
    (SEC, 4732): ("member added to local group", ["SubjectUserName", "MemberName", "MemberSid", "TargetUserName"], 3),
    (SEC, 4738): ("user account changed", ["SubjectUserName", "TargetUserName"], 2),
    (SEC, 4742): ("computer account changed", ["SubjectUserName", "TargetUserName"], 2),
    (SEC, 4768): ("Kerberos TGT requested", ["TargetUserName", "IpAddress", "TicketEncryptionType", "Status"], 1.5),
    (SEC, 4769): ("Kerberos service ticket requested", ["TargetUserName", "ServiceName", "IpAddress", "TicketEncryptionType", "Status"], 2),
    (SEC, 4776): ("NTLM credential validation", ["TargetUserName", "Workstation", "Status"], 1.5),
    (SEC, 4798): ("local user's groups enumerated", ["SubjectUserName", "TargetUserName", "CallerProcessName"], 2),
    (SEC, 4799): ("local group membership enumerated", ["SubjectUserName", "TargetUserName", "CallerProcessName"], 1.5),
    (SEC, 5136): ("directory object modified", ["SubjectUserName", "ObjectDN", "AttributeLDAPDisplayName", "AttributeValue", "OperationType"], 3),
    (SEC, 5140): ("network share accessed", ["SubjectUserName", "ShareName", "IpAddress"], 1.5),
    (SEC, 5145): ("network share object checked", ["SubjectUserName", "ShareName", "RelativeTargetName", "IpAddress", "AccessMask"], 2),
    (SEC, 5156): ("connection allowed", ["Application", "Direction", "DestAddress", "DestPort"], 0.8),
    (SEC, 5379): ("credential manager read", ["SubjectUserName", "TargetName", "CountOfCredentialsReturned"], 1),
    (PS, 4103): ("PowerShell pipeline", ["Payload"], 1.5),
    (PS, 4104): ("PowerShell script block", ["ScriptBlockText", "Path"], 3),
    ("PowerShell-classic", 400): ("PowerShell engine started", ["HostApplication"], 1.5),
    ("PowerShell-classic", 403): ("PowerShell engine stopped", ["HostApplication"], 0.5),
    ("PowerShell-classic", 600): ("PowerShell provider started", ["HostApplication"], 0.3),
    ("PowerShell-classic", 800): ("PowerShell pipeline", ["CommandLine", "Details"], 1),
    ("System", 104): ("event log cleared", ["SubjectUserName", "Channel"], 3),
    ("System", 7036): ("service state changed", ["param1", "param2"], 1),
    ("System", 7040): ("service start type changed", ["param1", "param2", "param3"], 2.5),
    ("System", 7045): ("service installed", ["ServiceName", "ImagePath", "ServiceType", "AccountName"], 3),
    ("WMI", 5857): ("WMI provider loaded", ["ProviderName", "ProviderPath"], 1),
    ("WMI", 5858): ("WMI query error", ["Operation", "ClientProcessId"], 0.5),
    ("WMI", 5860): ("WMI temporary subscription", ["Query", "User"], 2.5),
    ("WMI", 5861): ("WMI permanent subscription", ["Namespace", "ESS", "CONSUMER", "PossibleCause"], 3),
    ("TaskScheduler", 106): ("task registered", ["TaskName", "UserContext"], 2.5),
    ("TaskScheduler", 129): ("task process launched", ["TaskName", "Path"], 1.5),
    ("TaskScheduler", 140): ("task updated", ["TaskName", "UserName"], 1.5),
    ("TaskScheduler", 141): ("task deleted", ["TaskName", "UserName"], 2),
    ("TaskScheduler", 200): ("task action started", ["TaskName", "ActionName"], 1.5),
    ("BITS", 3): ("BITS job created", ["jobTitle", "jobOwner"], 2.5),
    ("BITS", 59): ("BITS transfer started", ["name", "url"], 2.5),
    ("Firewall", 2004): ("firewall rule added", ["RuleName", "ApplicationPath", "Direction", "Action", "LocalPorts"], 2.5),
    ("Firewall", 2006): ("firewall rule deleted", ["RuleName"], 2),
}
DEFAULT_WEIGHT = 0.4  # known channel, unlisted event id: shown only if very rare
LONG = {"CommandLine": 320, "ScriptBlockText": 400, "Payload": 240, "TaskContent": 320, "TaskContentNew": 200,
        "Details": 200, "Properties": 400, "Query": 300, "Destination": 400, "AttributeValue": 300, "Contents": 200}

GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", re.I)
HEX = re.compile(r"\b0x[0-9a-f]+\b", re.I)
SID = re.compile(r"\bS-1-5-21-[\d-]+\b", re.I)
MIXED = re.compile(r"\b(?=[A-Za-z_]*\d)(?=\d*[A-Za-z])[A-Za-z0-9_]{6,}\b")  # random ids: letters and digits mixed
NUM = re.compile(r"\b\d{2,}\b")
IP = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


def channel(e: dict) -> str | None:
    return CHANNELS.get(str(e.get("Channel") or "").lower())


def timestamp(e: dict) -> float | None:
    for k in ("@timestamp", "EventTime", "TimeCreated", "UtcTime"):
        v = e.get(k)
        if not v:
            continue
        v = str(v).replace("Z", "+00:00")
        for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                d = datetime.fromisoformat(v) if fmt is None else datetime.strptime(v[:26], fmt)
                return d.timestamp()
            except ValueError:
                continue
    return None


def short(v) -> str:
    s = re.sub(r"\s+", " ", str(v)).strip()
    return s


def classic_ps(e: dict) -> dict:
    """'Windows PowerShell' events keep everything in Message; pull out the useful lines."""
    m = str(e.get("Message") or "")
    out = {}
    for k in ("HostApplication", "CommandLine"):
        x = re.search(rf"\b{k}=([^\r\n]*)", m)
        if x and x.group(1).strip():
            out[k] = x.group(1).strip()
    x = re.search(r"Details:\s*(.*)", m, re.S)
    if x:
        out["Details"] = x.group(1).strip()
    return out


def fields(e: dict, ch: str, eid: int) -> tuple[str, list[tuple[str, str]], float]:
    label, keys, w = TYPES.get((ch, eid), (None, None, DEFAULT_WEIGHT))
    src = classic_ps(e) if ch == "PowerShell-classic" else e
    if keys is None:
        msg = str(e.get("Message") or "").split("\n")[0]
        return f"event {eid}", [("Message", msg)] if msg else [], w
    kv = []
    for k in keys:
        v = src.get(k)
        if v in (None, "", "-", "%%1793"):
            continue
        s = short(v)
        n = LONG.get(k, 160)
        kv.append((k, s if len(s) <= n else s[:n] + " …"))
    return label, kv, w


def template(ch: str, eid: int, kv: list[tuple[str, str]]) -> str:
    body = " ".join(f"{k}={v}" for k, v in kv)
    t = GUID.sub("<guid>", body)
    t = SID.sub("<sid>", t)
    t = HEX.sub("<hex>", t)
    t = MIXED.sub("<id>", t)
    t = NUM.sub("<n>", t)
    return f"{ch}:{eid} {t.lower()[:600]}"


def read_events(path: Path):
    with open(path, errors="replace") as fh:
        first = fh.read(1)
        fh.seek(0)
        if first == "[":
            yield from json.load(fh)
            return
        for line in fh:
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def parse(path: Path) -> dict:
    """One pass over a recording: group events by template."""
    groups: dict[str, dict] = {}
    n = 0
    hosts = Counter()
    for e in read_events(path):
        ch = channel(e)
        try:
            eid = int(e.get("EventID"))
        except (TypeError, ValueError):
            continue
        n += 1
        if not ch:
            continue
        label, kv, w = fields(e, ch, eid)
        if w <= 0 or not kv:
            continue
        host = str(e.get("Hostname") or e.get("host") or "?").split(".")[0].upper()
        hosts[host] += 1
        key = template(ch, eid, kv)
        t = timestamp(e)
        g = groups.get(key)
        if g is None:
            groups[key] = {"template": key, "channel": ch, "event_id": eid, "label": label, "weight": w,
                           "fields": dict(kv), "host": host, "first": t, "last": t, "count": 1, "hosts": {host}}
        else:
            g["count"] += 1
            g["hosts"].add(host)
            if t is not None:
                g["first"] = t if g["first"] is None else min(g["first"], t)
                g["last"] = t if g["last"] is None else max(g["last"], t)
    return {"events": n, "groups": groups, "hosts": dict(hosts)}


def score(g: dict, df: Counter, n_recordings: int) -> float:
    idf = math.log((n_recordings + 1) / (df[g["template"]] + 0.5))
    burst = 1 / (1 + math.log(g["count"]))
    return g["weight"] * max(idf, 0.0) * burst


CAPS = {(S, 7): 4, (S, 10): 6, (S, 12): 5, (S, 13): 7, (PS, 4103): 5, ("PowerShell-classic", 800): 4}  # per-type caps in the view


def condense(parsed: dict, df: Counter, n_recordings: int, view: int = 50, index: int = 1200,
             per_type: int = 14) -> dict:
    """Pick the triage view and the searchable index for one recording."""
    groups = list(parsed["groups"].values())
    for g in groups:
        g["score"] = score(g, df, n_recordings)
        g["fleet"] = df[g["template"]]  # how many recordings in the fleet contain this template
    groups.sort(key=lambda g: -g["score"])
    chosen, per = [], Counter()
    for g in groups:
        if g["score"] <= 0:
            break
        k = (g["channel"], g["event_id"])
        if per[k] >= CAPS.get(k, per_type):
            continue
        per[k] += 1
        chosen.append(g)
        if len(chosen) >= view:
            break
    idx = [g for g in groups if g["score"] > 0][:index]
    starts = [g["first"] for g in groups if g["first"] is not None]
    t0 = min(starts) if starts else 0.0

    def row(g):
        return {"t": round((g["first"] or t0) - t0, 1), "host": g["host"], "channel": g["channel"], "event_id": g["event_id"],
                "label": g["label"], "fields": g["fields"], "count": g["count"], "fleet": g["fleet"], "score": round(g["score"], 3)}

    view_rows = sorted((row(g) for g in chosen), key=lambda r: r["t"])
    for i, r in enumerate(view_rows, 1):
        r["id"] = f"E{i:03d}"
    chosen_ids = {id(g) for g in chosen}
    index_rows = sorted((row(g) for g in idx if id(g) not in chosen_ids), key=lambda r: r["t"])
    for i, r in enumerate(index_rows, 1):
        r["id"] = f"X{i:04d}"
    return {"events": parsed["events"], "templates": len(groups), "hosts": parsed["hosts"], "view": view_rows, "index": index_rows}


def line(r: dict, decode: bool = True) -> str:
    """How one event appears to the agents. Code-decoded meanings follow their value in ⟦ ⟧."""
    from .enrich import annotate
    ann = annotate(r["channel"], r["event_id"], r["fields"]) if decode else {}
    kv = " ".join((f'{k}="{v}"' if " " in v else f"{k}={v}") + (f" ⟦{ann[k]}⟧" if k in ann else "")
                  for k, v in r["fields"].items())
    rep = f" (x{r['count']})" if r["count"] > 1 else ""
    return f"[{r['id']}] +{r['t']:.0f}s {r['host']} {r['channel']} {r['event_id']} {r['label']}{rep}: {kv}"


def build_df(parsed_all: dict[str, dict]) -> Counter:
    df = Counter()
    for p in parsed_all.values():
        df.update(p["groups"].keys())
    return df
