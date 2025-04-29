import subprocess
import sys
import re
import time  # 경과 시간 측정을 위한 모듈
import csv

def run_jackalope_fuzzer(show_raw_output=False, run_duration=1800):
    # Jackalope 퍼저 실행 파일 (빌드된 바이너리 경로)
    binary = "/Users/gap_dev/fuzz_jack/Jackalope/build/Release/fuzzer"
    
    # 옵션: 각 옵션은 순서대로 전달합니다.
    options = [
        "-in", "./corpus_discovered",
        "-out", "./crashes",
        "-t", "4000",
        "-t1", "10000",
        "-instrument_module", "ImageIO",
        "-target_module", "test_imageio",
        "-target_method", "_fuzz",
        "-nargs", "1",
        "-iterations", "1000000",
        "-persist",
        "-loop",
        "-nthreads", "3",
        "-nargs", "1",
        "-cmp_coverage",
        "-generate_unwind"

    ]
    
    # fuzzer 명령어에 필요한 입력 자리표시자(@@) 추가 후 타깃 실행 파일 지정
    target_args = [
        "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio",
        "-f",
        "@@"
    ]
    
    # 전체 실행 커맨드는 fuzzer 옵션 이후에 '@@' (입력 파일 자리표시자)와 '--' 구분자를 두고 target_args를 추가하여 구성합니다.
    cmd = [binary] + options + ["@@", "--"] + target_args
    print("Executing:", " ".join(cmd))
    
    # 각 출력 항목을 위한 정규표현식들
    patterns = {
        "Total execs": re.compile(r"Total execs:\s*(\d+)"),
        "Unique samples": re.compile(r"Unique samples:\s*(\d+)"),
        "Crashes": re.compile(r"Crashes:\s*(\d+)"),
        "Hangs": re.compile(r"Hangs:\s*(\d+)"),
        "Offsets": re.compile(r"Offsets:\s*(\d+)"),
        "Execs/s": re.compile(r"Execs/s:\s*(\d+)"),
        "Fuzzing sample": re.compile(r"Fuzzing sample\s+(\S+)")
    }
    # Instrumented module 정보: 모듈명과 code size를 별도 칼럼(키는 "Instr {모듈명}")로 저장
    pattern_instr = re.compile(r"Instrumented module\s+([^,]+),\s*code size:\s*(\d+)")
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # 프로그램 시작 시각 기록
    start_time = time.time()
    results = []  # 파싱된 결과 저장 리스트 (나중에 CSV로 저장)
    current_record = {}  # 한 블록(레코드)별 데이터를 저장하는 딕셔너리

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed > run_duration:
                print("지정된 실행 시간(10분)이 경과되어 프로세스를 종료합니다.")
                process.terminate()
                break

            line = process.stdout.readline()
            if line == "" and process.poll() is not None:
                # 표준 출력이 끝나면 마지막 레코드를 저장
                if current_record:
                    # 현재 레코드에 elapsed time 추가
                    current_record["Elapsed Time"] = time.strftime("%Hh %Mm %Ss", time.gmtime(elapsed))
                    results.append(current_record)
                break
            if line:
                # 경과 시간 문자열 (현재 출력 시점)
                elapsed_str = time.strftime("%Hh %Mm %Ss", time.gmtime(elapsed))
                
                if show_raw_output:
                    sys.stdout.write(f"[{elapsed_str}] {line}")
                    sys.stdout.flush()
                
                line = line.strip()
                if not line:
                    continue  # 빈 줄은 무시
                
                # 만약 "Total execs:"로 시작하면 새로운 레코드 시작
                match_total = patterns["Total execs"].search(line)
                if match_total:
                    # 이전 레코드가 있으면 results에 추가하고, 새 레코드 시작
                    if current_record:
                        # 현재 레코드에 현재 시점 경과시간을 기록
                        current_record["Elapsed Time"] = elapsed_str
                        results.append(current_record)
                    current_record = {}
                    current_record["Total execs"] = match_total.group(1)
                    # 이후 다른 항목들도 같은 레코드에 추가될 것임.
                    continue
                
                # 다른 패턴 체크
                for key, pattern in patterns.items():
                    # "Total execs:"는 이미 처리했으므로 건너뜁니다.
                    if key == "Total execs":
                        continue
                    m = pattern.search(line)
                    if m:
                        current_record[key] = m.group(1)
                        break  # 해당 라인에서 하나의 항목만 추출한다고 가정

                # Instrumented module 정보 처리
                m_instr = pattern_instr.search(line)
                if m_instr:
                    module_name = m_instr.group(1)
                    code_size = m_instr.group(2)
                    current_record[f"Instr {module_name}"] = code_size
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
        # 모든 결과 레코드에서 등장한 키(칼럼) 집합 얻기
        fieldnames = set()
        for row in results:
            fieldnames.update(row.keys())
        # 원하는 칼럼 순서: Elapsed Time, Total execs, Unique samples, Crashes, Hangs, Offsets, Execs/s, 그 외는 알파벳 순으로 정렬
        fixed_cols = ["Elapsed Time", "Total execs", "Unique samples", "Crashes", "Hangs", "Offsets", "Execs/s", "Fuzzing sample"]
        remaining = sorted(field for field in fieldnames if field not in fixed_cols)
        fieldnames_ordered = fixed_cols + remaining

        with open(csv_filename, mode="w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames_ordered)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(f"결과가 CSV 파일({csv_filename})에 저장되었습니다.")

if __name__ == "__main__":
    # show_raw_output를 True로 하면 원본 로그를 타임스탬프와 함께 출력합니다.
    run_jackalope_fuzzer(show_raw_output=True)