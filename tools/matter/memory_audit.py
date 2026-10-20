#!/usr/bin/env python3
"""Measure private C layouts without linking, running or changing the library.

Requires a GCC-compatible compiler producing ELF objects and a matching nm.
Each probe includes one real implementation and declares sized marker symbols.
The selected compiler computes sizes; nm reads them from the object. Results are
layout costs, not a heap trace, linked flash size or a device acceptance test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


PROBES = {
    "runtime/matter_dispatch": {
        "dispatch": "sizeof(struct Matter_Dispatch)",
        "transaction": "sizeof(Transaction)",
        "transaction_packet": "PACKET",  # Upper bound; each TX allocates its encoded size.
        "transaction_packet_pointer": "sizeof(((Transaction*)0)->packet)",
        "transaction_links": "2 * sizeof(Transaction*)",
        "connections": "sizeof(((struct Matter_Dispatch*)0)->connections)",
        "connection": "sizeof(Connection)",
        "dispatch_packet_buffers": "4 * PACKET",
        "default_transactions": "MATTER_HOST_TRANSACTIONS * sizeof(Transaction)",  # Live-node ceiling, not idle allocation.
        "default_transactions_max_tx": "MATTER_HOST_TRANSACTIONS * (sizeof(Transaction) + PACKET)",
    },
    "model/matter_events": {
        "event_log": "sizeof(struct Matter_Events)",
        "event_record": "sizeof(Matter_Event_Record_T)",
        "event_log_records": "sizeof(((struct Matter_Events*)0)->records)",
        "event_log_pending": "sizeof(((struct Matter_Events*)0)->pending)",
    },
    "model/matter_im_read": {
        "read": "sizeof(struct Matter_Im_Read)",
        "read_events": "sizeof(ReadEvents)",
        "read_event_records": "sizeof(((ReadEvents*)0)->records)",
        "read_item": "sizeof(*((struct Matter_Im_Read*)0)->items)",
        "snapshot_budget": "MATTER_IM_READ_SNAPSHOT_BYTES",
    },
    "model/matter_im_subscribe": {
        "subscribe": "sizeof(struct Matter_Im_Subscribe)",
        "subscribe_events": "sizeof(SubEvents)",
        "subscribe_item": "sizeof(*((struct Matter_Im_Subscribe*)0)->items)",
        "subscribe_event_records": "sizeof(((SubEvents*)0)->records)",
    },
    "runtime/matter_store_host": {
        "store_host": "sizeof(struct Matter_Store_Host)",
        "store_work": "sizeof(Matter_Store_Data_T)",
        "store_blob": "MATTER_STORE_BLOB_MAX",
        "fabric_image": "sizeof(struct Matter_Fabric_Host_Image)",
    },
    "runtime/matter_fabric_host": {
        "fabric_host": "sizeof(struct Matter_Fabric_Host)",
        "fabric_backup": "sizeof(*((struct Matter_Fabric_Host*)0)->backup)",
        "resumptions": "sizeof(((struct Matter_Fabric_Host*)0)->resumption)",
    },
    "storage/matter_store_tlv": {"store_codec": "sizeof(Codec)", "store_codec_data": "sizeof(((Decoder*)0)->data)", "store_decoder": "sizeof(Decoder)"},
    "runtime/matter_runtime": {"runtime": "sizeof(struct Matter_Runtime)"},
    "transport/matter_exchange": {"exchange_table": "sizeof(struct Matter_Exchange_Table)"},
    "transport/matter_rx": {"rx": "sizeof(struct Matter_Rx)"},
    "transport/matter_ack": {"ack_table": "sizeof(struct Matter_Ack_Table)"},
    "transport/matter_retransmission": {"retransmission": "sizeof(struct Matter_Retransmission)"},
    "transport/matter_retransmission_sender": {"retransmission_sender": "sizeof(struct Matter_Retransmission_Sender)"},
    "transport/matter_unsecured": {"unsecured": "sizeof(struct Matter_Unsecured)"},
    "session/matter_secure": {"secure": "sizeof(struct Matter_Secure)"},
    "session/matter_case": {"case": "sizeof(struct Matter_Case)"},
    "session/matter_pase": {"pase": "sizeof(struct Matter_Pase)"},
    "model/matter_im_invoke": {"invoke": "sizeof(struct Matter_Im_Invoke)"},
    "model/matter_im_write": {"write": "sizeof(struct Matter_Im_Write)"},
    "model/matter_im_client": {"im_client": "sizeof(struct Matter_Im_Client)"},
    "clusters/matter_epm": {"epm": "sizeof(Epm)"},
    "clusters/matter_eem": {"eem": "sizeof(Eem)"},
    "clusters/matter_meter_source": {"meter_source": "sizeof(Source)"},
    "clusters/matter_diagnostics": {"diagnostics": "sizeof(struct Matter_Diagnostics)"},
    "clusters/matter_acl": {"acl": "sizeof(struct Matter_Acl)"},
    "matter": {"lifecycle": "sizeof(struct Matter)", "pointer": "sizeof(void*)"},
}


def run(command):
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{command!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--transport", type=int, default=56, help="Admission ceiling, 8..128 (default: 56)")
    parser.add_argument("--events", type=int, default=128, help="Event retention ceiling, 16..1024 (default: 128)")
    args = parser.parse_args()
    if not 8 <= args.transport <= 128 or not 16 <= args.events <= 1024:
        parser.error("--transport must be 8..128 and --events must be 16..1024")
    root = Path(__file__).resolve().parents[2]
    core = root / "main/apps/matter"
    output = args.output.resolve()
    if output == root or (root in output.parents and output.relative_to(root).parts[0] != "build"):
        parser.error("In-repository output must be inside build/")
    output.mkdir(parents=True, exist_ok=True)
    metrics, commands, hashes, diagnostics, stack = {}, [], {}, {}, []
    for source, expressions in PROBES.items():
        original = core / (source + ".c")
        stem = source.replace("/", "_")
        probe, obj = output / (stem + ".c"), output / (stem + ".o")
        markers = [f"const unsigned char memory_audit_{name}[{expr}] = {{0}};" for name, expr in expressions.items()]
        probe.write_text(f'#include "{original.as_posix()}"\n' + "\n".join(markers) + "\n", encoding="utf-8")
        command = [args.cc, "-std=c99", "-Os", "-Wall", "-Wextra", "-Werror", "-fstack-usage",
                   "-ffunction-sections", "-fdata-sections", f"-DMATTER_TRANSPORT_CAPACITY={args.transport}",
                   f"-DMATTER_EVENTS_CAPACITY={args.events}", "-I", str(core), "-c", str(probe), "-o", str(obj)]
        _, warning = run(command)
        symbols, _ = run([args.nm, "-S", "--radix=d", str(obj)])
        found = {}
        for line in symbols.splitlines():
            match = re.match(r"\s*\d+\s+(\d+)\s+\w\s+_?memory_audit_(\w+)$", line)
            if match:
                found[match[2]] = int(match[1])
        if set(found) != set(expressions):
            raise RuntimeError(f"Missing size markers for {source}: {set(expressions) - set(found)}. ELF symbol sizes are required (PE/COFF nm is unsupported).")
        metrics.update(found)
        commands.append(command)
        hashes[str(original.relative_to(root)).replace("\\", "/")] = hashlib.sha256(original.read_bytes()).hexdigest()
        if warning:
            diagnostics[source] = warning
        usage = obj.with_suffix(".su")
        if usage.exists():
            for line in usage.read_text().splitlines():
                parts = line.split("\t")
                if len(parts) == 3 and parts[1].isdigit():
                    stack.append({"function": parts[0], "bytes": int(parts[1]), "kind": parts[2]})
    result = {
        "revision": run(["git", "-C", str(root), "rev-parse", "HEAD"])[0].strip(),
        "compiler": run([args.cc, "--version"])[0].splitlines()[0],
        "transport_capacity": args.transport, "event_capacity": args.events,
        "scope": "Compile-only layout and individual function frames; no linked firmware or live heap measurement",
        "sizes": metrics, "largest_frames": sorted(stack, key=lambda x: x["bytes"], reverse=True)[:30],
        "diagnostics": diagnostics, "source_sha256": hashes, "commands": commands,
    }
    (output / "layouts.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"compiler": result["compiler"], "sizes": metrics, "warnings": diagnostics}, indent=2))


if __name__ == "__main__":
    main()
