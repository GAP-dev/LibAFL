use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
    thread,
};

use clap::Parser;
use once_cell::sync::Lazy;
use walkdir::WalkDir;

// rand
use rand::prelude::*;
use rand::thread_rng;
use ahash::AHasher;
use std::hash::{Hash, Hasher};

// libafl + bolts
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdMOptMutator, BytesSetMutator, ByteIncMutator},
    mutators::scheduled::StdScheduledMutator,
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasExecutions, StdState},
};
use libafl_tinyinst::executor::TinyInstExecutor;

/// Coverage map size
const MAP_SIZE: usize = 65536;

/// 전역 실행 횟수
static GLOBAL_EXECS: AtomicU64 = AtomicU64::new(0);

/// coverage offset의 총 개수
static GLOBAL_UNIQUE_OFFSETS: AtomicUsize = AtomicUsize::new(0);

/// 실제 coverage offset들을 보관
static GLOBAL_SHARED_OFFSETS: Lazy<Mutex<ahash::HashSet<u64>>> =
    Lazy::new(|| Mutex::new(ahash::HashSet::default()));

/// 최대 coverage count
static GLOBAL_MAX_THREAD_COV: AtomicUsize = AtomicUsize::new(0);

/// crash 횟수 제한
const MAX_CRASHES: usize = 3;

/// 한 시드에 대해 변이+실행 반복 횟수
const BATCH: usize = 10;

/// 스레드 간 시드 공유 주기(초)
const SYNC_INTERVAL: u64 = 5;

#[derive(Parser, Debug, Clone)]
struct Config {
    #[clap(long, default_value = "./corpus")]
    corpus_path: PathBuf,

    #[clap(long, default_value = "./crashes_all")]
    crashes_path: PathBuf,

    #[clap(long, default_value_t = 4)]
    forks: usize,

    #[clap(long, default_value_t = 2000)]
    timeout: u64,

    #[clap(long, default_value = "ImageIO")]
    tinyinst_module: String,

    #[clap(long)]
    tinyinst_extra: Option<String>,

    #[clap(long, default_value = "./target_app")]
    target: PathBuf,

    #[clap(last = true)]
    target_args: Vec<String>,
}

#[derive(Clone)]
struct ThreadParam {
    thread_id: usize,
    corpus_dir: PathBuf,
    crashes_dir: PathBuf,
    shared_unique_dir: PathBuf,
    tinyinst_args: Vec<String>,
    target_args: Vec<String>,
    timeout: u64,
}

/// (A) 에러 반환 타입을 `Result<..., Box<dyn Error + Send + Sync>>`로:
fn fuzz_thread_main(param: ThreadParam) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ThreadParam {
        thread_id,
        corpus_dir,
        crashes_dir,
        shared_unique_dir,
        tinyinst_args,
        target_args,
        timeout,
    } = param;

    // Observers
    let mut coverage_map = vec![0u64; MAP_SIZE];
    let cov_ptr: *mut Vec<u64> = &mut coverage_map as *mut Vec<u64>;
    let map_observer = unsafe { StdMapObserver::new("tinyinst_map", &mut coverage_map) };
    let time_observer = TimeObserver::new("time_observer");

    // Feedback
    let map_feedback = MaxMapFeedback::new(&map_observer);
    let mut feedback = feedback_or_fast!(map_feedback, TimeFeedback::new(&time_observer));
    let mut objective = CrashFeedback::new();

    // Random
    let rand = StdRand::with_seed(thread_id as u64 + 12345);

    // (B) 수동 변환: `?`를 쓰려면 `Result<..., libafl_bolts::Error>` → `Box<dyn Error + Send+Sync>`
    //     매번 `.map_err(|e| e.into())?`로 변환하거나, 아래처럼 `Box::new(e)`로 래핑:
    let inmem = InMemoryOnDiskCorpus::<BytesInput>::new(corpus_dir.clone())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    let ondisk = OnDiskCorpus::<BytesInput>::new(crashes_dir.clone())
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let mut state = StdState::new(rand, inmem, ondisk, &mut feedback, &mut objective)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Fuzzer
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut mgr = SimpleEventManager::new(MultiMonitor::new(|_s| {}));

    // TinyInstExecutor
    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(target_args)
        .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 1_000_000)
        .timeout(Duration::from_millis(timeout))
        .coverage_ptr(cov_ptr)
        .build(tuple_list!(map_observer, time_observer))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // 로컬 corpus load
    state
        .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_dir.clone()])
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Mutational pipeline: deterministic stage then havoc stage via StdScheduledMutator
    // 1) Deterministic mutator scheduler
    let det_sched = StdScheduledMutator::new(tuple_list!(
        BytesSetMutator::new(),      // 삽입/삭제
        ByteIncMutator::new()        // interesting-value 덮어쓰기
    ));
    let det_stage = StdMutationalStage::new(det_sched);

    // 2) Havoc mutator scheduler
    let havoc_sched = StdScheduledMutator::new(havoc_mutations());
    let havoc_stage = StdMutationalStage::new(havoc_sched);

    // Combine stages: deterministic first, then havoc
    let mut stages = tuple_list!(det_stage, havoc_stage);

    let mut last_sync = Instant::now();

    loop {
        let exec_before = *state.executions();

        for _ in 0..BATCH {
            executor.reset_last_crash();

            // fuzz_one 반환: Result<_, libafl::Error> or libafl_bolts::Error
            // -> BoxError로 변환
            let fuzz_result = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);

            if let Err(e) = fuzz_result {
                if let Some((crash_name, _is_unique, crash_count)) = executor.take_last_crash() {
                    eprintln!(
                        "[Thread {thread_id}] Duplicate crash {crash_name:?} (count={crash_count})"
                    );
                    break;
                } else {
                    return Err(e);
                }
            }

            // Crash?
            if let Some((crash_name, is_unique, crash_count)) = executor.take_last_crash() {
                println!(
                    "[Thread {thread_id}] Crash name: {:?}, total count = {}",
                    crash_name, crash_count
                );
                if is_unique || crash_count > MAX_CRASHES {
                    println!("[Thread {thread_id}] Possibly discarding after crash...");
                }
                break;
            }

            // coverage
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
                // 현재 testcase가 새 coverage 경로. => unique 폴더에 저장
                if let Some(cid_ref) = state.corpus().current() {
                    let cid = *cid_ref; // &CorpusId -> CorpusId
                    if let Ok(tc) = state.corpus().get(cid) {
                        if let Some(input) = tc.borrow().input() {
                            let data = input.as_ref();
                            let mut hasher = AHasher::default();
                            data.hash(&mut hasher);
                            let fp = hasher.finish();

                            let file_path = shared_unique_dir.join(format!("unique_{:016x}", fp));
                            if !file_path.exists() {
                                fs::write(&file_path, data)?;
                                println!(
                                    "[Thread {thread_id}] Found new coverage, saved to {:?}",
                                    file_path
                                );
                            }
                        }
                    }
                }
            }
            executor.hit_offsets_mut().clear();
        }

        let exec_after = *state.executions();
        GLOBAL_EXECS.fetch_add((exec_after - exec_before) as u64, Ordering::Relaxed);

        let total_cov = GLOBAL_UNIQUE_OFFSETS.load(Ordering::Relaxed);
        let mut prev = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);
        while total_cov > prev
            && GLOBAL_MAX_THREAD_COV
                .compare_exchange_weak(prev, total_cov, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            prev = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);
        }

        // 주기적 동기화
        let now = Instant::now();
        if now.duration_since(last_sync).as_secs() >= SYNC_INTERVAL {
            last_sync = now;
            let new_count = sync_from_unique(&shared_unique_dir, &corpus_dir)?;
            if new_count > 0 {
                println!("[Thread {thread_id}] Merged {new_count} new seeds from unique_samples");
                state
                    .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_dir.clone()])
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            }
        }
    }
}

/// 시드 폴더 동기화
fn sync_from_unique(
    unique_dir: &Path,
    corpus_dir: &Path,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut added = 0;
    for entry in fs::read_dir(unique_dir)? {
        let entry = entry?;
        let file_path = entry.path();
        if file_path.is_file() {
            let file_name = file_path.file_name().unwrap();
            let target_path = corpus_dir.join(file_name);
            if !target_path.exists() {
                fs::copy(&file_path, &target_path)?;
                added += 1;
            }
        }
    }
    Ok(added)
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::parse();

    let corpus_path = config.corpus_path.clone();
    let num_threads = config.forks;

    // 스캔
    let mut all_files = Vec::new();
    for entry in WalkDir::new(&corpus_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            all_files.push(entry.path().to_path_buf());
        }
    }
    println!("[Main] Found {} files in corpus", all_files.len());

    // 셔플 + partition
    let mut rng = thread_rng();
    all_files.shuffle(&mut rng);
    let mut partitions: Vec<Vec<PathBuf>> = vec![Vec::new(); num_threads];
    for (i, file_path) in all_files.into_iter().enumerate() {
        let idx = i % num_threads;
        partitions[idx].push(file_path);
    }

    // unique_samples 폴더
    let unique_samples_dir = PathBuf::from("unique_samples");
    fs::create_dir_all(&unique_samples_dir)?;

    // tinyinst, target args
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

    // 쓰레드 스폰
    let mut handles = Vec::new();
    for thread_id in 0..num_threads {
        let thread_input_dir = format!("thread_{thread_id}_input");
        let thread_crash_dir = format!("thread_{thread_id}_crashes");

        fs::create_dir_all(&thread_input_dir)?;
        fs::create_dir_all(&thread_crash_dir)?;

        // 분할된 파일 복사
        for file_path in &partitions[thread_id] {
            let filename = file_path.file_name().unwrap();
            let target = Path::new(&thread_input_dir).join(filename);
            fs::copy(file_path, &target)?;
        }

        let param = ThreadParam {
            thread_id,
            corpus_dir: PathBuf::from(&thread_input_dir),
            crashes_dir: PathBuf::from(&thread_crash_dir),
            shared_unique_dir: unique_samples_dir.clone(),
            tinyinst_args: tinyinst_args.clone(),
            target_args: target_args.clone(),
            timeout: config.timeout,
        };

        let handle = thread::spawn(move || fuzz_thread_main(param));
        handles.push(handle);
    }

    // Stats
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

    // Worker join
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("Worker error: {e}");
            }
            Err(e) => {
                eprintln!("Worker panicked: {:?}", e);
            }
        }
    }

    // stats_handle.join().unwrap();

    Ok(())
}