use std::{
    fs,
    path::PathBuf,
    thread,
    time::Duration,
};

use clap::Parser;
use libafl::state::HasCorpus;
use libafl::{
    feedback_or, feedback_or_fast,
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::{launcher::Launcher, EventConfig, SimpleEventManager},
    feedbacks::{CrashFeedback, ListFeedback, MapFeedback, MaxMapFeedback, TimeFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdMOptMutator},
    // MapObserver와 TimeObserver 사용
    observers::{StdMapObserver, TimeObserver},
    // 기본 큐 스케줄러 사용
    schedulers::QueueScheduler,
    // 기본 mutational stage (MOpt 독립 사용)
    stages::mutational::StdMutationalStage,
    state::{StdState, HasSolutions},
    Fuzzer, StdFuzzer,
};

use libafl_bolts::{
    core_affinity::Cores,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};

use libafl_tinyinst::executor::TinyInstExecutor;
use rand::Rng; // Rng 트레이트를 가져옵니다.

// coverage 맵 크기 (원소 개수)
const MAP_SIZE: usize = 65536;

// 전역 COVERAGE: TinyInst가 기록할 hit-count 정보를 저장  
// TinyInstExecutor는 *mut Vec<u64>를 요구합니다.
static mut COVERAGE: Vec<u64> = Vec::new();

/// Fuzzer 설정 (CLI 인자)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Config {
    #[clap(long, value_parser, default_value = "../../corpus_discovered")]
    corpus_path: PathBuf,

    #[clap(long, value_parser, default_value = "./crashes")]
    crashes_path: PathBuf,

    #[clap(long, default_value = "1337")]
    broker_port: u16,

    #[clap(long, default_value = "1")]
    forks: usize,

    #[clap(long, default_value = "100")]
    iterations: usize,

    #[clap(long, default_value = "100")]
    fuzz_iterations: usize,

    #[clap(long, default_value = "5")]
    loop_iterations: usize,

    #[clap(long, default_value = "4000")]
    timeout: u64,

    #[clap(long, default_value = "ImageIO")]
    tinyinst_module: String,

    #[clap(long)]
    tinyinst_extra: Option<String>,

    #[clap(long, value_parser)]
    target: PathBuf,

    #[clap(last = true)]
    target_args: Vec<String>,

    #[clap(long)]
    persistent_target: Option<String>,

    #[clap(long)]
    persistent_prefix: Option<String>,

    #[clap(long, default_value_t = 1)]
    persistent_iterations: usize,

    #[clap(long, default_value_t = 10000)]
    persistent_timeout: usize,
}

fn ensure_dir_exists(dir: &PathBuf) -> std::io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();
    ensure_dir_exists(&config.corpus_path)?;
    ensure_dir_exists(&config.crashes_path)?;
    env_logger::init();

    #[cfg(target_vendor = "apple")]
    {
        let socket_path = "./libafl_unix_shmem_server";
        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }
    }

    // TinyInst 인자 구성
    let mut tinyinst_args = vec![
        "-instrument_module".to_string(),
        config.tinyinst_module.clone(),
        "-generate_unwind".to_string(),
    ];
    if let Some(extra) = &config.tinyinst_extra {
        tinyinst_args.push(extra.clone());
    }

    // 타깃 실행 인자 구성
    let mut target_args = vec![config.target.to_string_lossy().into()];
    target_args.extend(config.target_args.iter().cloned());

    let corpus_path = config.corpus_path.clone();
    let crashes_path = config.crashes_path.clone();

    // COVERAGE 초기화
    unsafe {
        COVERAGE.resize(MAP_SIZE, 0);
    }

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let cores = Cores::from((0..config.forks).collect::<Vec<_>>());
    let broker_port = config.broker_port;

    Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("MyFuzzer"))
        .monitor(monitor.clone())
        .run_client(|_state, _mgr, _client| {
            let iterations = config.iterations;
            let base_rand = StdRand::new();

            for i in 0..iterations {
                println!("==> Starting fuzzing iteration {} in client", i + 1);

                // corpus 재로드
                let mut corpus = CachedOnDiskCorpus::new(corpus_path.clone(), 64)?;
                if let Ok(entries) = fs::read_dir(&corpus_path) {
                    for entry in entries.flatten() {
                        if let Some(filename) = entry.path().file_name().and_then(|n| n.to_str()) {
                            if filename.starts_with('.') {
                                continue;
                            }
                        }
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

                let solutions = OnDiskCorpus::new(crashes_path.clone())?;

                // MapObserver 생성: 내부 슬라이스(&mut [u64]) 제공
                let map_observer = unsafe { StdMapObserver::new("cov", &mut COVERAGE[..]) };
                let time_observer = TimeObserver::new("exec_time");

                // MOpt mutator를 포함하는 피드백 구조 구성
                let map_feedback = MaxMapFeedback::new(&map_observer);
                let mut feedback = feedback_or!(map_feedback, TimeFeedback::new(&time_observer));
                let mut objective = CrashFeedback::new();

                // State 생성
                let mut state = StdState::new(
                    base_rand.clone(),
                    corpus,
                    solutions,
                    &mut feedback,
                    &mut objective,
                )?;

                // 기본 큐 스케줄러 사용
                let scheduler = QueueScheduler::new();
                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                let mut event_manager = SimpleEventManager::new(monitor.clone());

                // TinyInstExecutor 빌드
                let builder = TinyInstExecutor::builder()
                    .tinyinst_args(tinyinst_args.clone())
                    .program_args(target_args.clone())
                    .timeout(Duration::from_millis(config.timeout));

                let builder = if let (Some(p_target), Some(p_prefix)) =
                    (config.persistent_target.clone(), config.persistent_prefix.clone())
                {
                    builder.persistent(p_target, p_prefix, config.persistent_iterations, config.persistent_timeout)
                } else {
                    builder
                };

                let mut executor = builder
                    .coverage_ptr(unsafe { &mut COVERAGE as *mut Vec<u64> })
                    .build(tuple_list!(map_observer, time_observer))?;

                // MOpt mutator를 독립적으로 사용하기 위해 기본 mutational stage로 감싸기
                let mopt_mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)?;
                let mopt_stage = StdMutationalStage::new(mopt_mutator);
                let mut stages = tuple_list!(mopt_stage);

                // fuzzing 루프 실행
                for k in 0..config.fuzz_iterations {
                    fuzzer.fuzz_one(
                        &mut stages,
                        &mut executor,
                        &mut state,
                        &mut event_manager,
                    )?;
                    println!(
                        "Pid: {}, Tid: {:?} | Iteration {} - Coverage count: {} | Corpus entries: {} | Crashes: {}",
                        std::process::id(),
                        std::thread::current().id(),
                        k + 1,
                        executor.hit_offsets().len(),
                        state.corpus().count(),
                        state.solutions().count()
                    );
                    /*if k % 100000 == 0 {
                        // 새로운 seed 파일들 추가
                        if let Ok(entries) = fs::read_dir(&corpus_path) {
                            for entry in entries.flatten() {
                                if let Some(filename) = entry.path().file_name().and_then(|n| n.to_str()) {
                                    if filename.starts_with('.') {
                                        continue;
                                    }
                                }
                                let data = match fs::read(&entry.path()) {
                                    Ok(d) => d,
                                    Err(err) => {
                                        eprintln!("Failed to read file {:?}: {}", entry.path(), err);
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
                    }*/
                }
            }
            Ok(())
        })
        .cores(&cores)
        .broker_port(broker_port)
        .build()
        .launch::<BytesInput, ()>()?;

    Ok(())
}