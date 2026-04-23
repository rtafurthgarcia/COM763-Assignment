#!/usr/bin/env python3
"""
Parse a network measurement CSV and export to JSON.

Expected CSV header:
    id,origin,ground_truth,guess,ip_v4,ip_v6,latency,hops,count,date_time

Usage:
    python csv_to_json.py input.csv output.json
"""

import csv
import json
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional


def parse_csv_to_dicts(csv_path: str) -> List[Dict[str, Any]]:
    """
    Read CSV and convert each row into a typed dictionary.

    Args:
        csv_path: Path to the input CSV file.

    Returns:
        List of dictionaries with correctly typed values.
    """
    rows = []

    try:
        with open(csv_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)

            # Optional header validation
            expected = ["id", "origin", "ground_truth", "guess", "ip_v4",
                        "ip_v6", "latency", "hops", "count", "date_time"]
            if reader.fieldnames != expected:
                print(f"Warning: header mismatch.\nExpected: {expected}\nFound: {reader.fieldnames}", file=sys.stderr)

            for line_num, row in enumerate(reader, start=2):  # line 1 is header
                try:
                    parsed = {}

                    # Integer fields
                    parsed['id'] = int(row['id']) if row['id'].strip() else None

                    # String fields (empty string becomes empty string)
                    parsed['origin'] = row['origin'].strip()
                    parsed['country'] = row['ground_truth'].strip()
                    parsed['ip_v4'] = row['ip_v4'].strip() if row['ip_v4'] else None
                    parsed['ip_v6'] = row['ip_v6'].strip() if row['ip_v6'] else None

                    if parsed['origin'] != "NordVPN":
                        rows.append(parsed)

                except (ValueError, KeyError) as e:
                    print(f"Skipping row {line_num} due to error: {e}", file=sys.stderr)
                    print(f"Row content: {row}", file=sys.stderr)
                    continue

    except FileNotFoundError:
        print(f"Error: CSV file '{csv_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error reading CSV: {e}", file=sys.stderr)
        sys.exit(1)

    return rows


def write_json(data: List[Dict[str, Any]], json_path: str, indent: int = 2) -> None:
    """
    Write list of dictionaries to a JSON file.

    Args:
        data: Data to write.
        json_path: Output file path.
        indent: JSON indentation level.
    """
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        print(f"Successfully wrote {len(data)} records to {json_path}")
    except Exception as e:
        print(f"Error writing JSON: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) != 3:
        print("Usage: python csv_to_json.py <input.csv> <output.json>")
        sys.exit(1)

    csv_input = sys.argv[1]
    json_output = sys.argv[2]

    parsed_data = parse_csv_to_dicts(csv_input)
    if not parsed_data:
        print("No valid rows found. Exiting.")
        sys.exit(1)

    write_json(parsed_data, json_output)

    # Optional: print first record as preview
    print("\nPreview of first record:")
    for key, value in parsed_data[0].items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()