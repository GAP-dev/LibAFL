import subprocess
import sys
import re
import time  # 경과 시간 측정을 위한 모듈

def run_rust_fuzzer(show_raw_output=False):
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
    
    try:
        while True:
            # 실시간으로 한 줄씩 읽기
            line = process.stdout.readline()
            if line == "" and process.poll() is not None:
                break
            if line:
                # 경과 시간 계산 (초 단위)
                elapsed = time.time() - start_time
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
                    # 파싱된 결과를 경과 시간과 함께 출력
                    print(f"[{elapsed_str}][ViFuzz 1.0] Pid: {pid}, Iteration: {iteration}, Coverage count: {coverage_count}, Corpus entries: {corpus_entries}, Crashes: {crashes}")
                    
    except KeyboardInterrupt:
        print("Terminated by user.")
    finally:
        # stderr 출력 (필요할 경우)
        err = process.stderr.read()
        if err:
            sys.stderr.write(err)
        retcode = process.wait()
        print("Process exited with code:", retcode)

if __name__ == "__main__":
    # show_raw_output 매개변수를 False로 설정하면 파싱된 결과만 보입니다.
    # stdout 원본 로그도 보고 싶을 경우 True로 변경하면 됩니다.
    run_rust_fuzzer(show_raw_output=False)