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

def find_input_files_recursive(base_folder):
    """
    base_folder 하위에서
    1) 폴더 이름이 'thread'로 시작하거나
    2) 폴더 이름이 'corpus_'로 시작하는 폴더에 대해서만
    재귀적으로 파일들을 수집하여 리스트로 반환.
    """
    input_files = []

    # base_folder 바로 아래 디렉토리들을 순회
    for entry in os.scandir(base_folder):
        # 디렉토리인 경우 확인
        if entry.is_dir():
            # 폴더 이름이 조건에 맞는지 확인
            if entry.name.startswith("thread") or entry.name.startswith("corpus_"):
                # 조건에 맞는 디렉토리 내부를 재귀적으로 탐색
                for root, _, files in os.walk(entry.path):
                    for file in files:
                        if file.startswith('.'):
                            # 숨김 파일은 스킵
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
        print(f"[✓] {os.path.basename(input_file)}: {len(local_offsets)} offsets "
              f"({len(all_offsets)} total unique)")

def main():
    parser = argparse.ArgumentParser(description="Parallel litecov runner with live offset count")
    parser.add_argument("--input-folder", required=True, help="Root folder of input files")
    args = parser.parse_args()

    # 지정 폴더 하위에서, 'thread...' 또는 'corpus_...' 로 시작하는 폴더만 탐색
    files = find_input_files_recursive(args.input_folder)
    print(f"[+] Found {len(files)} input files from 'thread*' or 'corpus_*' folders.\n")

    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = [executor.submit(run_litecov_single, f) for f in files]
        for future in as_completed(futures):
            # 내부 예외는 run_litecov_single에서 처리
            future.result()

    print(f"\n[✓] Final total unique offsets: {len(all_offsets)}")

if __name__ == "__main__":
    main()