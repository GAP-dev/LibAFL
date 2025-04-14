use std::{
    fs,
    path::PathBuf,
    sync::atomic::AtomicBool,
    thread,
    time::Duration,
};

use clap::Parser;
use libafl::state::HasCorpus;
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::{launcher::Launcher, EventConfig, SimpleEventManager},
    feedbacks::{CrashFeedback, ListFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::ListObserver,
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
    ownedref::OwnedMutPtr,
};

use libafl_tinyinst::executor::TinyInstExecutor;

// 추가: 랜덤 딜레이를 위해 rand 사용
use rand::Rng;

// coverage 맵 크기 (원소 개수)
const MAP_SIZE: usize = 65536;

// 전역 COVERAGE: TinyInst가 기록할 hit-count 정보를 저장  
// TinyInstExecutor는 *mut Vec<u64>를 요구합니다.
static mut COVERAGE: Vec<u64> = Vec::new();

/// Fuzzer 설정 (CLI 인자)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Config {
    /// Corpus 디렉토리 경로 (seed 파일들이 위치)
    #[clap(long, value_parser, default_value = "../../corpus_discovered")]
    corpus_path: PathBuf,

    /// Crashes 디렉토리 경로 (크래시 케이스 저장용)
    #[clap(long, value_parser, default_value = "./crashes")]
    crashes_path: PathBuf,

    /// Broker 포트 번호
    #[clap(long, default_value = "1337")]
    broker_port: u16,

    /// 사용할 코어(포크) 수
    #[clap(long, default_value = "1")]
    forks: usize,

    /// 클라이언트 반복 횟수 (전체 fuzzing iteration 수)
    #[clap(long, default_value = "100")]
    iterations: usize,

    #[clap(long, default_value = "5")]
    loop_iterations: usize,

    /// 각 반복 내 fuzzing 루프 횟수
    #[clap(long, default_value = "100")]
    fuzz_iterations: usize,

    /// 타임아웃 (밀리초 단위)
    #[clap(long, default_value = "4000")]
    timeout: u64,

    /// TinyInst용 instrument 모듈 이름
    #[clap(long, default_value = "ImageIO")]
    tinyinst_module: String,

    /// 추가 TinyInst 인자 (옵션)
    #[clap(long)]
    tinyinst_extra: Option<String>,

    /// 타깃 실행 파일 경로 (반드시 지정)
    #[clap(long, value_parser)]
    target: PathBuf,

    /// 타깃 인자 (target 실행 시 전달할 추가 인자들)
    #[clap(last = true)]
    target_args: Vec<String>,

    /// persistent 모드: 타깃 모듈 이름 (옵션; 지정되면 persistent 모드 활성)
    #[clap(long)]
    persistent_target: Option<String>,

    /// persistent 모드: 추가 접두어 (옵션; persistent_target와 모두 지정되어야 함)
    #[clap(long)]
    persistent_prefix: Option<String>,

    /// persistent 모드: 반복 횟수 (default 1)
    #[clap(long, default_value_t = 1)]
    persistent_iterations: usize,

    /// persistent 모드: 타임아웃 (default 10000)
    #[clap(long, default_value_t = 10000)]
    persistent_timeout: usize,
}

fn remove_hidden_files(dir: &PathBuf) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        if let Ok(entry) = entry {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with('.') {
                    fs::remove_file(&path)?;
                }
            }
        }
    }
    Ok(())
}

fn ensure_dir_exists(dir: &PathBuf) -> std::io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI 인자 파싱
    let config = Config::parse();
    
    // corpus와 crashes 디렉토리 존재 확인 (없으면 생성)
    ensure_dir_exists(&config.corpus_path)?;
    ensure_dir_exists(&config.crashes_path)?;

    // env_logger 초기화 (로그 출력은 stderr)
    env_logger::init();

    // macOS 환경: TinyInst용 이전 유닉스 소켓 파일 제거 (필요시)
    #[cfg(target_vendor = "apple")]
    {
        let socket_path = "./libafl_unix_shmem_server";
        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }
    }

    // TinyInst에 전달할 인자 구성
    let mut tinyinst_args = vec![
        "-instrument_module".to_string(),
        config.tinyinst_module.clone(),
        "-generate_unwind".to_string(),
    ];
    if let Some(extra) = &config.tinyinst_extra {
        tinyinst_args.push(extra.clone());
    }

    // 대상 프로그램 인자 구성: 첫번째 인자는 타깃 실행 파일 경로, 그 뒤에 추가 인자들을 전달
    let mut target_args = vec![config.target.to_string_lossy().into()];
    target_args.extend(config.target_args.iter().cloned());

    // corpus 및 crashes 디렉토리 경로 복사
    let corpus_path = config.corpus_path.clone();
    let crashes_path = config.crashes_path.clone();

    // corpus 디렉토리 내 숨김 파일 제거
    remove_hidden_files(&corpus_path)?;

    // 전역 COVERAGE 벡터를 MAP_SIZE만큼 0으로 초기화
    unsafe {
        COVERAGE.resize(MAP_SIZE, 0);
    }

    // 병렬 실행을 위한 모니터 설정 (출력은 stdout)
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // 공용 Shared Memory Provider 초기화
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // 사용할 코어 설정 (config.forks 개)
    let cores = Cores::from((0..config.forks).collect::<Vec<_>>());
    let broker_port = config.broker_port;

    // Launcher를 통해 병렬 클라이언트 실행
    Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("MyFuzzer"))
        .monitor(monitor.clone())
        .run_client(|_state, _mgr, _client| {
            // 각 클라이언트가 시작될 때 500ms ~ 2000ms 사이의 랜덤 딜레이를 둡니다.
            let delay_ms = rand::thread_rng().gen_range(0..4000);
            println!("Waiting for {} ms before client initialization...", delay_ms);
            thread::sleep(Duration::from_millis(delay_ms));

            let iterations = config.iterations;
            let base_rand = StdRand::new();

            for i in 0..iterations {
                println!("==> Starting fuzzing iteration {} in client", i + 1);

                // corpus 내 숨김 파일 제거 및 corpus 재로드
                remove_hidden_files(&corpus_path)?;
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

                // Crash 케이스 저장용 corpus 생성
                let solutions = OnDiskCorpus::new(crashes_path.clone())?;

                // --- Observer 생성 ---
                // ListObserver를 전역 COVERAGE에 대한 포인터로 생성합니다.
                let coverage_ptr = OwnedMutPtr::Ptr(unsafe { &mut COVERAGE });
                let list_observer = ListObserver::new("cov", coverage_ptr);

                // --- Feedback 생성 ---
                let mut feedback = ListFeedback::new(&list_observer);
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
                let builder = TinyInstExecutor::builder()
                    .tinyinst_args(tinyinst_args.clone())
                    .program_args(target_args.clone())
                    .timeout(Duration::from_millis(config.timeout));

                let builder = if let (Some(p_target), Some(p_prefix)) = (
                    config.persistent_target.clone(),
                    config.persistent_prefix.clone(),
                ) {
                    builder.persistent(p_target, p_prefix, config.persistent_iterations, config.persistent_timeout)
                } else {
                    builder
                };

                // executor에 ListObserver를 사용하여 빌드합니다.
                let mut executor = builder
                    .coverage_ptr(unsafe { &mut COVERAGE as *mut Vec<u64> })
                    .build(tuple_list!(list_observer))?;

                // --- Mutator 및 Stage 생성 ---
                let mutator = StdScheduledMutator::new(havoc_mutations());
                let mut stages = tuple_list!(StdMutationalStage::new(mutator));

                // --- Fuzzing 루프 실행 ---
                for _ in 0..config.fuzz_iterations {
                    fuzzer.fuzz_loop_for(
                        &mut stages,
                        &mut executor,
                        &mut state,
                        &mut event_manager,
                        config.loop_iterations as u64,
                    )?;
                    println!(
                        "Pid: {}, Tid: {:?} | Iteration {} - Coverage count: {} | Corpus entries: {}",
                        std::process::id(),
                        std::thread::current().id(),
                        i + 1,
                        executor.hit_offsets().len(),
                        state.corpus().count()
                    );

                    // 추가 seed 파일들 처리
                    if let Ok(entries) = fs::read_dir(&corpus_path) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                                if filename.starts_with('.') {
                                    continue;
                                }
                            }
                            let data = match fs::read(&path) {
                                Ok(d) => d,
                                Err(err) => {
                                    eprintln!("Failed to read file {:?}: {}", path, err);
                                    continue;
                                }
                            };
                            let already_present = state.corpus().ids().any(|id| {
                                if let Ok(testcase_cell) = state.corpus().get(id) {
                                    let testcase = testcase_cell.borrow();
                                    if let Some(input) = testcase.input() {
                                        input.as_ref() == data.as_slice()
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            });
                            if already_present {
                                continue;
                            }
                            let input = BytesInput::new(data);
                            state.corpus_mut().add(Testcase::new(input))?;
                        }
                    }
                }
            }
            Ok(())
        })
        .cores(&cores)
        .broker_port(broker_port)
        .build() // build()는 Result가 아닌 Launcher를 반환합니다.
        .launch::<BytesInput, ()>()?;

    Ok(())
}