"""
One-off helper for an existing soar.db.

1. Extracts IOCs (public IPs, file hashes) from alerts that were
   ingested before IOC extraction existed, and links them.
2. Optionally removes the placeholder intelligence created by
   Database.seed_mock_iocs() so the real VirusTotal lookup can run
   for those IOCs (--clear-mock-intel).

It never contacts VirusTotal. Back up soar.db first.

Usage:
    python backfill_iocs.py --dry-run
    python backfill_iocs.py
    python backfill_iocs.py --clear-mock-intel
    python backfill_iocs.py --db path/to/soar.db
"""

import argparse
import json

from database import Database
from ioc_extractor import extract_iocs


def backfill(database, dry_run=False):
    alerts = database.fetch_all(
        "SELECT id, src_ip, dst_ip, raw_event FROM alerts"
    )

    new_iocs = set()
    links = 0

    for alert in alerts:
        event = None

        if alert["raw_event"]:
            try:
                event = json.loads(alert["raw_event"])
            except ValueError:
                event = None

        for value, ioc_type in extract_iocs(
            alert["src_ip"],
            alert["dst_ip"],
            event
        ):
            if dry_run:
                if database.get_ioc_by_value(value) is None:
                    new_iocs.add(value)
                links += 1
                continue

            if database.get_ioc_by_value(value) is None:
                new_iocs.add(value)

            ioc_id = database.add_ioc(value, ioc_type)
            database.link_ioc_to_alert(alert["id"], ioc_id)
            links += 1

    return len(alerts), len(new_iocs), links


def clear_mock_intel(database, dry_run=False):
    """
    Placeholder intelligence has no raw_data. Real results from the
    enrichment worker always store raw_data, so they are kept.
    """

    rows = database.fetch_all(
        """
        SELECT ii.id, i.value, ii.source, ii.score
        FROM ioc_intelligence AS ii
        INNER JOIN iocs AS i ON ii.ioc_id = i.id
        WHERE ii.status = 'Cached Intelligence Available'
          AND ii.raw_data IS NULL
        """
    )

    for row in rows:
        print(
            f"  mock intel: {row['value']} "
            f"({row['source']}, {row['score']})"
        )

        if not dry_run:
            database.execute(
                "DELETE FROM ioc_intelligence WHERE id = ?",
                (row["id"],)
            )

    return len(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--clear-mock-intel", action="store_true")
    args = parser.parse_args()

    database = Database(db_path=args.db) if args.db else Database()

    scanned, new_iocs, links = backfill(database, args.dry_run)

    label = "would add" if args.dry_run else "added"
    print(
        f"Scanned {scanned} alerts: {label} {new_iocs} new IOCs, "
        f"{links} alert-IOC links processed."
    )

    if args.clear_mock_intel:
        removed = clear_mock_intel(database, args.dry_run)
        verb = "would remove" if args.dry_run else "removed"
        print(f"{verb.capitalize()} {removed} mock intelligence rows.")


if __name__ == "__main__":
    main()
