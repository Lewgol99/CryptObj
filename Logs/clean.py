import sys

def dedupe(input_path, output_path):
    seen = set()
    total = 0
    kept = 0

    with open(input_path, "r", encoding="utf-8", errors="replace") as infile, \
         open(output_path, "w", encoding="utf-8") as outfile:
        for line in infile:
            total += 1
            if line not in seen:
                seen.add(line)
                outfile.write(line)
                kept += 1

    print(f"Read {total} lines, kept {kept} unique lines, removed {total - kept} duplicates.")
    print(f"Output written to: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dedupe_log.py input.log output.log")
        sys.exit(1)

    dedupe(sys.argv[1], sys.argv[2])
