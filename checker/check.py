import os
import subprocess
import tempfile
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

LITECOV_PATH = "/Users/gap_dev/fuzz_jack/last_dance/LibAFL/checker/TinyInst/litecov"
TARGET_BIN = "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio"

offsets_lock = threading.Lock()
all_offsets = set()

def find_input_files_recursive(folder):
    input_files = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.startswith('.'):
                continue
            full_path = os.path.join(root, file)
            if os.path.isfile(full_path):
                input_files.append(full_path)
    return input_files

def run_litecov_single(input_file):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        coverage_file = tmp.name

    cmd = [
        LITECOV_PATH,
        
        "-generate_unwind",
        "-instrument_module", "ImageIO",
        "-cmp_coverage",
        "-coverage_file", coverage_file,
        "--",
        TARGET_BIN,
        "-f", input_file
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print(f"[!] Failed on: {input_file}")
        os.remove(coverage_file)
        return

    local_offsets = set()
    try:
        with open(coverage_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    local_offsets.add(line)
    finally:
        os.remove(coverage_file)

    with offsets_lock:
        added = local_offsets - all_offsets
        all_offsets.update(local_offsets)
        print(f"[✓] {os.path.basename(input_file)}: {len(local_offsets)} offsets ({len(all_offsets)} total unique)")

def main():
    parser = argparse.ArgumentParser(description="Parallel litecov runner with live offset count")
    parser.add_argument("--input-folder", required=True, help="Root folder of input files")
    args = parser.parse_args()

    files = find_input_files_recursive(args.input_folder)
    print(f"[+] Found {len(files)} input files (recursively, excluding dotfiles)\n")

    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = [executor.submit(run_litecov_single, f) for f in files]
        for future in as_completed(futures):
            future.result()  # exceptions handled inside worker

    print(f"\n[✓] Final total unique offsets: {len(all_offsets)}")

if __name__ == "__main__":
    main()