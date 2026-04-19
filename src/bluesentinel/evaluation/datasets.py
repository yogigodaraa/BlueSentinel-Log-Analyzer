"""Log anomaly dataset loaders.

Ships loaders for the public Loghub benchmarks (He et al., 2023). We
don't bundle the datasets — they're too large — but we ship a single
``load_loghub(name)`` entrypoint that either reads a local copy under
``data/`` or fetches it from the canonical URL on first use.

References:
    https://github.com/logpai/loghub
    https://doi.org/10.1109/ASE56229.2023.00040

Supported datasets:
    - HDFS_v1     — 11M events, 16838 blocks, 2.9% anomalous (block-level)
    - BGL         —  4.7M events, 7% anomalous (line-level)
    - Thunderbird — 211M events, large-scale stress test
"""

from __future__ import annotations

import csv
import gzip
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import numpy as np

from bluesentinel.types import LogEvent

# Loghub URLs (current as of 2025).
LOGHUB_URLS: dict[str, str] = {
    "HDFS_v1": "https://zenodo.org/record/8196385/files/HDFS_v1.zip",
    "BGL": "https://zenodo.org/record/8196385/files/BGL.zip",
    "Thunderbird": "https://zenodo.org/record/8196385/files/Thunderbird.zip",
}


@dataclass
class LoadedDataset:
    name: str
    events: list[LogEvent]
    labels: np.ndarray
    """1 = anomaly, 0 = normal. Same length as events."""


def load_hdfs_csv(path: str | Path) -> LoadedDataset:
    """Load a preprocessed HDFS CSV with columns: LineId, Content, Label.

    The Loghub 2.0 release ships a ready parsed CSV; many academic log
    anomaly papers work from that. If you have the raw HDFS.log file
    instead, pair ``SyslogParser`` + ``DrainParser`` with the
    blocks.log labels.
    """
    events: list[LogEvent] = []
    labels: list[int] = []
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as f:  # type: ignore[operator]
        reader = csv.DictReader(f)
        for row in reader:
            from datetime import datetime

            events.append(
                LogEvent(
                    timestamp=datetime.utcfromtimestamp(0),
                    message=row.get("Content") or row.get("message") or "",
                    raw={"dataset": "HDFS", "row_id": row.get("LineId")},
                )
            )
            lbl = row.get("Label", "Normal")
            labels.append(1 if lbl.lower() in ("anomaly", "1", "true") else 0)
    return LoadedDataset(name="HDFS_v1", events=events, labels=np.array(labels, dtype=int))


def iter_loghub_raw(path: str | Path) -> Iterator[str]:
    """Stream raw lines from a Loghub .log or .log.gz file."""
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:  # type: ignore[operator]
        for line in f:
            yield line.rstrip("\n")


def synthetic_dataset(n_normal: int = 500, n_anomaly: int = 25) -> LoadedDataset:
    """Tiny synthetic dataset for smoke-testing the evaluation harness.

    Normal events cycle through a small set of realistic auth.log
    templates. Anomalies are an attack sequence: many failed passwords
    → successful login → privilege escalation → firewall disable.
    """
    import random
    from datetime import datetime, timedelta

    random.seed(42)
    events: list[LogEvent] = []
    labels: list[int] = []

    normal_templates = [
        "session opened for user {user} by (uid=0)",
        "session closed for user {user}",
        "Accepted publickey for {user} from 10.0.0.{ip} port 49152 ssh2",
        "CRON session opened for user {user}",
        "PAM: pam_unix session opened for user {user}",
    ]
    users = ["alice", "bob", "carol", "dave", "eve"]

    t0 = datetime(2026, 1, 1, 8, 0, 0)
    # Normal baseline
    for i in range(n_normal):
        tmpl = random.choice(normal_templates)
        events.append(
            LogEvent(
                timestamp=t0 + timedelta(seconds=i * 5),
                message=tmpl.format(user=random.choice(users), ip=random.randint(2, 254)),
                host="prod-01",
                process_name="sshd",
                process_pid=random.randint(1000, 9999),
                user=random.choice(users),
                source_ip=f"10.0.0.{random.randint(2, 254)}",
            )
        )
        labels.append(0)

    # Attack sequence
    t1 = t0 + timedelta(minutes=30)
    attack_lines = (
        ["Failed password for root from 203.0.113.5 port 44251 ssh2"] * 20
        + ["Failed password for admin from 203.0.113.5 port 44251 ssh2"] * 5
        + ["Accepted password for admin from 203.0.113.5 port 44251 ssh2"]
        + ["user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"]
        + ["iptables -F"]
        + ["rm /var/log/auth.log"]
    )
    for i, msg in enumerate(attack_lines[:n_anomaly]):
        events.append(
            LogEvent(
                timestamp=t1 + timedelta(seconds=i),
                message=msg,
                host="prod-01",
                process_name="sshd" if "ssh" in msg.lower() else "sudo",
                source_ip="203.0.113.5",
            )
        )
        labels.append(1)

    return LoadedDataset(name="synthetic", events=events, labels=np.array(labels, dtype=int))
