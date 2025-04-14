use std::{
    fs,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::Duration,
};
use libafl::state::HasCorpus;
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::{launcher::Launcher, EventConfig, SimpleEventManager},
    feedbacks::{CrashFeedback, map::MaxMapFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{StdMapObserver, HitcountsMapObserver},
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};

use libafl_bolts::{
    core_affinity::Cores,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};

use libafl_tinyinst::executor::TinyInstExecutor;

// coverage 맵 크기 (원소 개수)
const MAP_SIZE: usize = 65536;

// 전역 COVERAGE: TinyInst가 기록할 hit-count 정보를 저장  
// TinyInstExecutor는 *mut Vec<u64>를 요구합니다.
static FUZZING: AtomicBool = AtomicBool::new(true);
static mut COVERAGE: Vec<u64> = Vec::new();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // env_logger 초기화 (로그 출력은 stderr)
    env_logger::init();

    // macOS 환경: 이전의 TinyInst용 유닉스 소켓 파일 제거 (필요시)
    #[cfg(target_vendor = "apple")]
    {
        let socket_path = "./libafl_unix_shmem_server";
        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }
    }

    // TinyInst에 전달할 인자
    let tinyinst_args = vec![
        "-instrument_module".to_string(),
        "ImageIO".to_string(),
        // 필요시: "-ignore_exceptions".to_string(),
    ];

    // 대상 프로그램 인자
    let args = vec![
        "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio".to_string(),
        "-f".to_string(),
        "@@".to_string(),
    ];

    // corpus 및 crashes 디렉토리 경로
    let corpus_path = PathBuf::from("../../corpus_discovered");
    let crashes_path = PathBuf::from("./crashes");

    // corpus 디렉토리 내 숨김 파일(. 으로 시작하는 파일) 제거
    for entry in fs::read_dir(&corpus_path)? {
        if let Ok(entry) = entry {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with('.') {
                    fs::remove_file(&path)?;
                }
            }
        }
    }

    // 전역 COVERAGE 벡터를 MAP_SIZE만큼 0으로 초기화
    unsafe {
        COVERAGE.resize(MAP_SIZE, 0);
    }

    // 병렬 실행을 위한 모니터 설정
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // 공용 Shared Memory Provider 초기화
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // 사용할 코어 설정 (예: 3개)
    let forks = 3;
    let cores = Cores::from((0..forks).collect::<Vec<_>>());
    let broker_port = 1337;

    // Launcher를 통해 병렬로 클라이언트를 실행
    Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("MyFuzzer"))
        .monitor(monitor.clone())
        .run_client(|_state, _mgr, _client| {
            // 각 클라이언트는 여러 iteration 동안 corpus를 재로드
            let iterations = 3;
            let base_rand = StdRand::new();

            for i in 0..iterations {
                println!("==> Starting fuzzing iteration {} in client", i + 1);

                // iteration 시작 시 corpus 디렉토리 내 숨김 파일 제거
                for entry in fs::read_dir(&corpus_path)? {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                            if filename.starts_with('.') {
                                fs::remove_file(&path)?;
                            }
                        }
                    }
                }

                // 디스크의 corpus 재로드
                let mut corpus = CachedOnDiskCorpus::new(corpus_path.clone(), 64)?;
                if let Ok(entries) = fs::read_dir(&corpus_path) {
                    for entry in entries.flatten() {
                        if let Ok(data) = fs::read(entry.path()) {
                            let input = BytesInput::new(data);
                            corpus.add(Testcase::new(input))?;
                        }
                    }
                }
                if corpus.count() == 0 {
                    return Err(libafl::Error::illegal_state(
                        "Corpus is empty. Please add at least one seed file.".to_string(),
                    )
                    .into());
                }

                // crashes corpus (크래시 케이스 저장용)
                let solutions = OnDiskCorpus::new(crashes_path.clone())?;

                // --- Observer 생성 ---
                // TinyInstExecutor는 COVERAGE가 Vec<u64>여야 하지만,
                // feedback/observer는 기본적으로 u8 슬라이스를 기대하므로,  
                // COVERAGE의 메모리를 바이트 슬라이스로 재해석합니다.
                let coverage_slice: &mut [u8] = unsafe {
                    std::slice::from_raw_parts_mut(
                        COVERAGE.as_mut_ptr() as *mut u8,
                        COVERAGE.len() * std::mem::size_of::<u64>(),
                    )
                };

                // StdMapObserver는 이름과 u8 슬라이스를 받습니다.
                let std_map_observer = unsafe {
                    StdMapObserver::new("coverage_map", coverage_slice)
                };

                // HitcountsMapObserver로 감싸서 사용
                let map_observer = HitcountsMapObserver::new(std_map_observer);

                // --- Feedback 생성 ---
                // 기본 alias인 MaxMapFeedback는 내부 Reducer를 기본적으로 사용하므로,
                // generics 없이 with_name으로 생성합니다.
                let mut feedback = MaxMapFeedback::with_name("max_map_feedback", &map_observer);
                let mut objective = CrashFeedback::new();

                // --- State 생성 ---
                let mut state = StdState::new(
                    base_rand.clone(),
                    corpus,
                    solutions,
                    &mut feedback,
                    &mut objective,
                )?;

                // Fuzzer 및 스케줄러 생성
                let scheduler = RandScheduler::new();
                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                // 이벤트 매니저 생성
                let mut event_manager = SimpleEventManager::new(monitor.clone());

                // --- Executor 생성 ---
                // TinyInstExecutor는 coverage_ptr에 전역 COVERAGE 벡터의 포인터 (*mut Vec<u64>)를 필요로 합니다.
                let mut executor = TinyInstExecutor::builder()
                    .tinyinst_args(tinyinst_args.clone())
                    .program_args(args.clone())
                    .timeout(Duration::from_millis(4000))
                    .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 10000)
                    .coverage_ptr(unsafe { &mut COVERAGE as *mut Vec<u64> })
                    // Observer를 튜플로 전달
                    .build(tuple_list!(map_observer))?;

                // --- Mutator 및 Stage 생성 ---
                let mutator = StdScheduledMutator::new(havoc_mutations());
                let mut stages = tuple_list!(StdMutationalStage::new(mutator));

                // --- Fuzzing 루프 실행 ---
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets().len(),
                    state.corpus().count()
                );



                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
                    .expect("error in fuzzing loop");

                // iteration 종료 후 현재 커버리지 데이터를 출력
                println!(
                    "Iteration {} - Coverage data: {:?} | Imported {} inputs from disk.",
                    i + 1,
                    executor.hit_offsets(),
                    state.corpus().count()
                );
            }
            Ok(())
        })
        .cores(&cores)
        .broker_port(broker_port)
        .build()
        .launch::<BytesInput, ()>()?;

    Ok(())
}