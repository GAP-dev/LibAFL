use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use rand::thread_rng;
use clap::Parser;
use once_cell::sync::Lazy;
use walkdir::WalkDir;
use ahash::AHasher;
use std::hash::{Hash, Hasher};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl::{
    
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdMOptMutator},
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasExecutions, StdState},
};
use libafl_tinyinst::executor::TinyInstExecutor;

/// TinyInst 커버리지 맵 크기 (u64 단위)
const MAP_SIZE: usize = 65536;
/// 바이트로 계산할 때
const MAP_BYTES: usize = MAP_SIZE * 8;

/// 커버리지 보고를 위해 전역으로 보관
static GLOBAL_EXECS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_UNIQUE_OFFSETS: AtomicUsize = AtomicUsize::new(0);

/// 전역 Set으로 새 오프셋 기록
static GLOBAL_SHARED_OFFSETS: Lazy<Mutex<ahash::HashSet<u64>>> =
    Lazy::new(|| Mutex::new(ahash::HashSet::default()));

/// 최대 coverage count
static GLOBAL_MAX_THREAD_COV: AtomicUsize = AtomicUsize::new(0);

/// crash 횟수 제한
const MAX_CRASHES: usize = 3;

/// 각 스레드가 수행할 배치 (한 번 corpus 아이템 골랐을 때 몇 번 변이+실행)
const BATCH: usize = 10;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
struct Config {
    /// 전체 corpus 경로
    #[clap(long, value_parser, default_value = "./corpus")]
    corpus_path: PathBuf,

    /// (Optional) Crash 아웃풋(전역) 저장 경로
    #[clap(long, value_parser, default_value = "./crashes_all")]
    crashes_path: PathBuf,

    /// 스레드(= 파티션) 개수
    #[clap(long, default_value_t = 4)]
    forks: usize,

    /// timeout(ms)
    #[clap(long, default_value_t = 2000)]
    timeout: u64,

    #[clap(long, default_value = "ImageIO")]
    tinyinst_module: String,

    #[clap(long)]
    tinyinst_extra: Option<String>,

    /// 타겟 실행 파일
    #[clap(long, value_parser, default_value = "./target_app")]
    target: PathBuf,

    /// 타겟에 넘길 인자
    #[clap(last = true)]
    target_args: Vec<String>,
}

/// worker 스레드 함수 파라미터
#[derive(Clone)]
struct ThreadParam {
    thread_id: usize,
    corpus_dir: PathBuf,  // 이 스레드만의 corpus 폴더
    crashes_dir: PathBuf, // 이 스레드만의 crashes 폴더
    tinyinst_args: Vec<String>,
    target_args: Vec<String>,
    timeout: u64,
}

/// worker 스레드 메인
fn fuzz_thread_main(param: ThreadParam) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ThreadParam {
        thread_id,
        corpus_dir,
        crashes_dir,
        tinyinst_args,
        target_args,
        timeout,
    } = param;

    // (1) 커버리지 맵, Observers
    let mut coverage_map = vec![0u64; MAP_SIZE];
    let cov_ptr: *mut Vec<u64> = &mut coverage_map as *mut Vec<u64>;
    // unsafe지만 실제 lifetime 맞춰서 사용
    let map_observer = unsafe { StdMapObserver::new("tinyinst_map", &mut coverage_map) };
    let time_observer = TimeObserver::new("time_observer");

    // (2) Feedback, Objective
    let map_feedback = MaxMapFeedback::new(&map_observer);
    let mut feedback = feedback_or_fast!(map_feedback, TimeFeedback::new(&time_observer));
    let mut objective = CrashFeedback::new();

    // (3) State
    let rand = StdRand::with_seed(thread_id as u64 + 12345);
    let mut state = StdState::new(
        rand,
        // 이 스레드 전용 corpus 폴더
        InMemoryOnDiskCorpus::<BytesInput>::new(corpus_dir.clone())?,
        // 이 스레드 전용 crash 폴더
        OnDiskCorpus::<BytesInput>::new(crashes_dir.clone())?,
        &mut feedback,
        &mut objective,
    )?;

    // (4) Fuzzer
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // (5) Event manager
    let mut mgr = SimpleEventManager::new(MultiMonitor::new(|_s| {}));

    // (6) TinyInstExecutor (Persistent 모드 예시)
    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(target_args)
        .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 1_000_000)
        .timeout(Duration::from_millis(timeout))
        .coverage_ptr(cov_ptr)
        .build(tuple_list!(map_observer, time_observer))?;

    // (7) corpus load
    let _ = state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_dir]);

    // (8) Mutator
    let mopt = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)?;
    let mut stages = tuple_list!(StdMutationalStage::new(mopt));

    // (9) fuzz loop
    loop {
        // 스케줄러가 pick할 아이템(로컬 corpus에서)
        // 한 아이템에 대해 BATCH번 변이+실행
        // libafl의 fuzz_one()은 자동으로 state.corpus().current()를 고릅니다
        // QueueScheduler는 round-robin 등등

        let exec_before = *state.executions();

        // BATCH번 시도
        for _ in 0..BATCH {
            executor.reset_last_crash();

            let fuzz_result = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr);
            if let Err(e) = fuzz_result {
                // crash 검출?
                if let Some((crash_name, _is_unique, crash_count)) = executor.take_last_crash() {
                    eprintln!(
                        "[Thread {thread_id}] Duplicate crash {crash_name:?} (count={crash_count})"
                    );
                    // 굳이 corpus에서 discard할 필요가 있으면 이 스레드 로컬 corpus 내 로직 가능
                    // 여기서는 단순 로그만
                    break;
                } else {
                    return Err(Box::new(e));
                }
            }

            // crash?
            if let Some((crash_name, is_unique, crash_count)) = executor.take_last_crash() {
                println!(
                    "[Thread {thread_id}] Crash name: {:?}, total count = {}",
                    crash_name, crash_count
                );
                if is_unique || crash_count > MAX_CRASHES {
                    println!(
                        "[Thread {thread_id}] (optional) Discarding after crash... (not implemented)"
                    );
                }
                break;
            }

            // coverage update
            let hits = executor.hit_offsets();
            let mut newly_found = 0;
            {
                let mut global_offs = GLOBAL_SHARED_OFFSETS.lock().unwrap();
                for &off in hits {
                    if global_offs.insert(off) {
                        newly_found += 1;
                    }
                }
            }
            if newly_found > 0 {
                GLOBAL_UNIQUE_OFFSETS.fetch_add(newly_found, Ordering::Relaxed);
            }
            executor.hit_offsets_mut().clear();
        }

        let exec_after = *state.executions();
        GLOBAL_EXECS.fetch_add((exec_after - exec_before) as u64, Ordering::Relaxed);

        // GLOBAL_MAX_THREAD_COV 갱신
        let total_cov = GLOBAL_UNIQUE_OFFSETS.load(Ordering::Relaxed);
        let mut prev = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);
        while total_cov > prev
            && GLOBAL_MAX_THREAD_COV
                .compare_exchange_weak(prev, total_cov, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            prev = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();

    let corpus_path = config.corpus_path.clone();
    let global_crashes_path = config.crashes_path.clone();
    let num_threads = config.forks;

    // Step 1) 전체 corpus 파일 로딩
    let mut all_files = Vec::new();
    for entry in WalkDir::new(&corpus_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            all_files.push(entry.path().to_path_buf());
        }
    }
    println!("[Main] Found {} files in corpus", all_files.len());

    // Step 2) 셔플 + 분할
    //  - 그냥 균등 분할. 추가적으로 slice_chunks 등 사용 가능
    //  - 아래서는 단순 round robin 분배
    use rand::prelude::*;
    let mut rng = thread_rng();
    all_files.shuffle(&mut rng);

    let mut partitions: Vec<Vec<PathBuf>> = vec![Vec::new(); num_threads];
    for (i, file_path) in all_files.into_iter().enumerate() {
        let idx = i % num_threads;
        partitions[idx].push(file_path);
    }

    // Step 3) 스레드별로 corpus_dir, crashes_dir 준비
    //  - 예: thread_{id}_input, thread_{id}_crashes
    let mut threads = Vec::new();
    let mut tinyinst_args = vec![
        "-instrument_module".to_string(),
        config.tinyinst_module.clone(),
        "-generate_unwind".to_string(),
    ];
    if let Some(extra) = config.tinyinst_extra.clone() {
        tinyinst_args.push(extra);
    }
    let mut target_args = vec![config.target.to_string_lossy().into_owned()];
    target_args.extend(config.target_args.clone());

    for thread_id in 0..num_threads {
        let thread_input_dir = format!("thread_{thread_id}_input");
        let thread_crash_dir = format!("thread_{thread_id}_crashes");

        // 폴더 생성
        std::fs::create_dir_all(&thread_input_dir)?;
        std::fs::create_dir_all(&thread_crash_dir)?;

        // 해당 스레드가 담당하는 corpus 파일 복사(또는 symlink)
        // 여기서는 간단히 복사
        for file_path in &partitions[thread_id] {
            let filename = file_path.file_name().unwrap();
            let target = Path::new(&thread_input_dir).join(filename);

            // 만약 크기가 큰 파일이 많다면 symlink를 권장
            // 여기서는 예제 상 실제로 복사
            std::fs::copy(file_path, &target)?;
        }

        // ThreadParam
        let param = ThreadParam {
            thread_id,
            corpus_dir: PathBuf::from(&thread_input_dir),
            crashes_dir: PathBuf::from(&thread_crash_dir),
            tinyinst_args: tinyinst_args.clone(),
            target_args: target_args.clone(),
            timeout: config.timeout,
        };

        // 스레드 스폰
        let handle = thread::spawn(move || fuzz_thread_main(param));
        threads.push(handle);
    }

    // Step 4) stats thread
    let stats_handle = thread::spawn(move || {
        let mut prev_execs = 0u64;
        let mut smoothed_speed = 0u64;
        const ALPHA: f64 = 0.2;

        loop {
            thread::sleep(Duration::from_secs(1));

            let execs = GLOBAL_EXECS.load(Ordering::Relaxed);
            let speed = execs - prev_execs;
            smoothed_speed =
                ((speed as f64) * ALPHA + (smoothed_speed as f64) * (1.0 - ALPHA)).round() as u64;
            prev_execs = execs;

            let offsets_set_size = {
                let set = GLOBAL_SHARED_OFFSETS.lock().unwrap();
                set.len()
            };
            let max_cov = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);

            println!(
                "[Stats] coverage {:>8}, exec/s {:>10} (avg {:>10}), total_execs {:>12}, maxcov={}",
                offsets_set_size, speed, smoothed_speed, execs, max_cov
            );
        }
    });

    // Step 5) workers join
    for handle in threads {
        match handle.join() {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("Worker error: {e}");
            }
            Err(e) => {
                eprintln!("Worker panicked: {:?}", e);
            }
        }
    }

    // 필요하다면 stats thread 종료 로직
    // stats_handle.join().unwrap();

    Ok(())
}