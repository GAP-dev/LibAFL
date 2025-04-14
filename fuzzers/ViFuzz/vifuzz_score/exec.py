import subprocess
import sys
import re
import time  # 경과 시간 측정을 위한 모듈
import csv

def run_rust_fuzzer(show_raw_output=False, run_duration=600):
    # Rust fuzzer 실행 파일 이름 (빌드된 바이너리 경로)
    binary = "../target/debug/ViFuzz"
    
    # 옵션: 각 옵션은 '--option value' 형식으로 전달합니다.
    options = [
        "--target", "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio",
        "--corpus-path", "./corpus_discovered",
        "--crashes-path", "./crashes",
        "--broker-port", "8888",
        "--forks", "7",
        "--iterations", "1",
        "--fuzz-iterations", "10000",
        "--loop-iterations", "100",
        "--timeout", "4000",
        "--tinyinst-module", "ImageIO",
        "--persistent-target", "test_imageio",
        "--persistent-prefix", "_fuzz"
        # 필요시 추가 인자 또는 persistent 옵션을 여기서 추가할 수 있습니다.
    ]
    
    # 타깃 인자: 옵션 이후의 위치 인자로 전달합니다.
    target_args = ["-f", "@@"]
    
    # 전체 실행 커맨드는 옵션과 위치 인자 사이에 '--' 구분자를 추가하여 구성합니다.
    cmd = [binary] + options + ["--"] + target_args
    print("Executing:", " ".join(cmd))
    
    # 패턴 2 : "Pid: ..." 형식 (Crashes 추가)
    pattern_iteration = re.compile(
        r"Pid:\s*(\d+),\s*Tid:[^|]+\|\s*Iteration\s+(\d+)\s*-\s*Coverage count:\s+(\d+)\s*\|\s*Corpus entries:\s+(\d+)\s*\|\s*Crashes:\s+(\d+)"
    )
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # 프로그램 시작 시각 기록
    start_time = time.time()
    results = []  # 파싱된 결과 저장 리스트 (CSV로 저장할 예정)
    
    try:
        while True:
            # 10분(600초) 경과 시 자동 종료
            elapsed = time.time() - start_time
            if elapsed > run_duration:
                print("지정된 실행 시간(10분)이 경과되어 프로세스를 종료합니다.")
                process.terminate()
                break
            
            # 실시간으로 한 줄씩 읽기
            line = process.stdout.readline()
            if line == "" and process.poll() is not None:
                break
            if line:
                # 경과 시간 계산 (초 단위)
                hrs, rem = divmod(int(elapsed), 3600)
                mins, secs = divmod(rem, 60)
                elapsed_str = f"{hrs}h {mins}m {secs}s"
                
                # 원본 로그 출력 옵션이 활성화된 경우 (타임스탬프와 함께)
                if show_raw_output:
                    sys.stdout.write(f"[{elapsed_str}] {line}")
                    sys.stdout.flush()
                
                # 패턴 2 매칭: Pid ... Iteration ... 형식 (Crashes 포함)
                match_iter = pattern_iteration.search(line)
                if match_iter:
                    pid            = match_iter.group(1)
                    iteration      = match_iter.group(2)
                    coverage_count = match_iter.group(3)
                    corpus_entries = match_iter.group(4)
                    crashes        = match_iter.group(5)
                    
                    # 파싱된 결과를 리스트에 저장
                    results.append({
                        "Elapsed Time": elapsed_str,
                        "Pid": pid,
                        "Iteration": iteration,
                        "Coverage Count": coverage_count,
                        "Corpus Entries": corpus_entries,
                        "Crashes": crashes
                    })
                    
                    # 파싱된 결과를 경과 시간과 함께 출력
                    print(f"[{elapsed_str}][ViFuzz 1.0] Pid: {pid}, Iteration: {iteration}, Coverage count: {coverage_count}, Corpus entries: {corpus_entries}, Crashes: {crashes}")
                    
    except KeyboardInterrupt:
        print("사용자에 의해 종료되었습니다.")
    finally:
        # stderr 출력 (필요할 경우)
        err = process.stderr.read()
        if err:
            sys.stderr.write(err)
        retcode = process.wait()
        print("프로세스 종료 코드:", retcode)
        
        # CSV 파일 저장
        csv_filename = "results.csv"
        with open(csv_filename, mode="w", newline="") as csvfile:
            fieldnames = ["Elapsed Time", "Pid", "Iteration", "Coverage Count", "Corpus Entries", "Crashes"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(f"결과가 CSV 파일({csv_filename})에 저장되었습니다.")

if __name__ == "__main__":
    # show_raw_output 매개변수를 False로 설정하면 파싱된 결과만 보입니다.
    # stdout 원본 로그도 보고 싶을 경우 True로 변경하면 됩니다.
    run_rust_fuzzer(show_raw_output=False)