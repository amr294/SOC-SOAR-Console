import argparse
import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "soar.db"


def get_alert_columns(connection):
    rows = connection.execute(
        "PRAGMA table_info(alerts)"
    ).fetchall()

    return {
        row[1]
        for row in rows
    }


def main():
    parser = argparse.ArgumentParser(
        description="Add Wazuh source-event columns/indexes to an existing SOAR database."
    )
    parser.add_argument(
        "--db",
        default=str(DB_PATH),
        help=f"Existing SQLite database path (default: {DB_PATH})"
    )
    args = parser.parse_args()
    db_path = Path(args.db).expanduser().resolve()
    if not db_path.is_file():
        parser.error(
            f"Database does not exist: {db_path}. This migration is for an existing database; "
            "back it up first and pass --db if it is not at the default path."
        )

    print()
    print("==========================================")
    print("WAZUH DATABASE SCHEMA MIGRATION")
    print("==========================================")
    print(f"Database: {db_path}")

    connection = sqlite3.connect(db_path)

    try:
        columns = get_alert_columns(connection)

        if "source_severity" not in columns:
            print("Adding column: source_severity")
            connection.execute(
                "ALTER TABLE alerts ADD COLUMN source_severity INTEGER"
            )
        else:
            print("Column already exists: source_severity")

        if "event_timestamp" not in columns:
            print("Adding column: event_timestamp")
            connection.execute(
                "ALTER TABLE alerts ADD COLUMN event_timestamp TEXT"
            )
        else:
            print("Column already exists: event_timestamp")

        duplicates = connection.execute(
            """
            SELECT
                source,
                source_event_id,
                COUNT(*) AS count
            FROM alerts
            WHERE source_event_id IS NOT NULL
            GROUP BY source, source_event_id
            HAVING COUNT(*) > 1
            """
        ).fetchall()

        if duplicates:
            raise RuntimeError(
                "Duplicate source events exist. "
                "Resolve them before creating the unique index: "
                f"{duplicates}"
            )

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_event
            ON alerts(source, source_event_id)
            WHERE source_event_id IS NOT NULL
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_event_timestamp
            ON alerts(event_timestamp)
            """
        )

        connection.commit()

        print()
        print("Migration completed successfully.")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    main()