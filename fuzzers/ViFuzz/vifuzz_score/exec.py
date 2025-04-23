import subprocess
import sys
import re
import time  # 경과 시간 측정을 위한 모듈
import csv

def run_rust_fuzzer(show_raw_output=False, run_duration=1800):
    # Rust fuzzer 실행 파일 이름 (빌드된 바이너리 경로)
    binary = "../target/debug/ViFuzz"
    
    # 옵션: 각 옵션은 '--option value' 형식으로 전달합니다.
    options = [
        "--target", "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio",
        "--corpus-path", "./corpus_discovered",
        "--crashes-path", "./crashes",
        "--forks", "10",
    ]
    
    # 타깃 인자: 옵션 이후의 위치 인자로 전달합니다.
    target_args = ["-f", "@@"]
    
    # 전체 실행 커맨드는 옵션과 위치 인자 사이에 '--' 구분자를 추가하여 구성합니다.
    cmd = [binary] + options + ["--"] + target_args
    print("Executing:", " ".join(cmd))
    
    # 
    # (구) 패턴1(Iteration), 패턴2([ViFuzz] STATS:) 부분은 제거하고
    # 아래처럼 [Stats] 커맨드에 매칭되는 정규식을 추가합니다.
    #
    # 예: [Stats] coverage    14806, exec/s          0 (avg        965), total_execs      2236045, maxcov=14806
    #
    # 그룹핑:
    #  1) coverage
    #  2) exec/s
    #  3) avg exec/s
    #  4) total_execs
    #  5) maxcov
    #
    pattern_stats = re.compile(
        r"\[Stats\]\s*coverage\s+(\d+),\s*exec/s\s+(\d+)\s*\(avg\s+(\d+)\),\s*total_execs\s+(\d+),\s*maxcov=(\d+)"
    )
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # 프로그램 시작 시각 기록
    start_time = time.time()
    results = []  # 파싱된 결과를 저장할 리스트 (이후 CSV로 저장)
    
    try:
        while True:
            # 지정된 시간(run_duration) 경과 시 자동 종료
            elapsed = time.time() - start_time
            if elapsed > run_duration:
                print("지정된 실행 시간이 경과되어 프로세스를 종료합니다.")
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
                
                # 원본 로그 출력 옵션
                if show_raw_output:
                    sys.stdout.write(f"[{elapsed_str}] {line}")
                    sys.stdout.flush()
                
                # (1) [Stats] 로그 파싱
                match_stats = pattern_stats.search(line)
                if match_stats:
                    coverage    = match_stats.group(1)
                    exec_s      = match_stats.group(2)
                    avg_exec_s  = match_stats.group(3)
                    total_execs = match_stats.group(4)
                    maxcov      = match_stats.group(5)
                    
                    # 파싱된 결과를 리스트에 저장
                    results.append({
                        "Elapsed Time": elapsed_str,
                        "Coverage": coverage,
                        "Exec/s": exec_s,
                        "Avg Exec/s": avg_exec_s,
                        "Total Execs": total_execs,
                        "MaxCov": maxcov,
                    })
                    
                    # 콘솔에 표시
                    print(
                        f"[{elapsed_str}][Stats] "
                        f"coverage: {coverage}, "
                        f"exec/s: {exec_s}, "
                        f"(avg: {avg_exec_s}), "
                        f"total_execs: {total_execs}, "
                        f"maxcov: {maxcov}"
                    )
                    
    except KeyboardInterrupt:
        print("사용자에 의해 종료되었습니다.")
    finally:
        # stderr 출력
        err = process.stderr.read()
        if err:
            sys.stderr.write(err)
        
        retcode = process.wait()
        print("프로세스 종료 코드:", retcode)
        
        # CSV 파일로 저장
        csv_filename = "results.csv"
        with open(csv_filename, mode="w", newline="") as csvfile:
            fieldnames = [
                "Elapsed Time",
                "Coverage",
                "Exec/s",
                "Avg Exec/s",
                "Total Execs",
                "MaxCov",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(f"결과가 CSV 파일({csv_filename})에 저장되었습니다.")

if __name__ == "__main__":
    # show_raw_output를 True로 설정하면 원본 로그를 그대로 콘솔에 표시합니다.
    run_rust_fuzzer(show_raw_output=True)