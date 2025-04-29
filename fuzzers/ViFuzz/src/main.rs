use std::{
    fs,
    io,
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
    mutators::{havoc_mutations, BytesSetMutator, ByteIncMutator, StdMOptMutator},
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

/// 새롭게 발견된 coverage offset들을 모아두는 리스트 (통계 표시 용도)
static GLOBAL_NEW_OFFSETS: Lazy<Mutex<Vec<u64>>> = Lazy::new(|| Mutex::new(vec![]));

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

    /// 각 스레드가 사용할 개수
    #[clap(long, default_value_t = 4)]
    forks: usize,

    #[clap(long, default_value_t = 2000)]
    timeout: u64,

    #[clap(long, default_value = "ImageIO")]
    tinyinst_module: String,

    /// TinyInst에 추가로 넣을 인자(옵션)
    #[clap(long)]
    tinyinst_extra: Option<String>,

    /// 타겟 실행 파일 경로
    #[clap(long, default_value = "./target_app")]
    target: PathBuf,

    /// 타겟 실행 인자
    #[clap(last = true)]
    target_args: Vec<String>,

    /// **글로벌 큐 폴더** (모든 스레드가 공유)
    #[clap(long, default_value = "./global_queue")]
    global_queue_path: PathBuf,
}

#[derive(Clone)]
struct ThreadParam {
    thread_id: usize,
    local_corpus_dir: PathBuf,
    crashes_dir: PathBuf,
    global_queue_dir: PathBuf,
    tinyinst_args: Vec<String>,
    target_args: Vec<String>,
    timeout: u64,
}

/// 로컬 폴더 → 글로벌 큐 폴더로 파일을 복사(새 파일만)
fn sync_local_to_global(
    local_dir: &Path,
    global_dir: &Path,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut synced = 0;
    for entry in fs::read_dir(local_dir)? {
        let entry = entry?;
        let file_path = entry.path();
        if file_path.is_file() {
            let file_name = file_path.file_name().unwrap();
            let target = global_dir.join(file_name);
            if !target.exists() {
                fs::copy(&file_path, &target)?;
                synced += 1;
            }
        }
    }
    Ok(synced)
}

/// 글로벌 큐 폴더 → 로컬 폴더로 파일을 복사(새 파일만)
fn sync_global_to_local(
    global_dir: &Path,
    local_dir: &Path,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut synced = 0;
    for entry in fs::read_dir(global_dir)? {
        let entry = entry?;
        let file_path = entry.path();
        if file_path.is_file() {
            let file_name = file_path.file_name().unwrap();
            let target = local_dir.join(file_name);
            if !target.exists() {
                fs::copy(&file_path, &target)?;
                synced += 1;
            }
        }
    }
    Ok(synced)
}

/// 스레드 메인 루프
fn fuzz_thread_main(param: ThreadParam) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ThreadParam {
        thread_id,
        local_corpus_dir,
        crashes_dir,
        global_queue_dir,
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

    // Corpus
    let inmem = InMemoryOnDiskCorpus::<BytesInput>::new(local_corpus_dir.clone())
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
        .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[local_corpus_dir.clone()])
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Mutational pipeline
    let det_sched = StdScheduledMutator::new(tuple_list!(
        BytesSetMutator::new(), // 삽입/삭제
        ByteIncMutator::new()   // interesting-value 덮어쓰기
        // 필요하다면 StdMOptMutator 등 추가 가능
    ));
    let det_stage = StdMutationalStage::new(det_sched);

    let havoc_sched = StdScheduledMutator::new(havoc_mutations());
    let havoc_stage = StdMutationalStage::new(havoc_sched);

    let mut stages = tuple_list!(det_stage, havoc_stage);

    let mut last_sync = Instant::now();

    loop {
        let exec_before = *state.executions();

        // BATCH만큼 테스트
        for _ in 0..BATCH {
            executor.reset_last_crash();

            let fuzz_result = fuzzer
                .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
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

            // coverage 체크
            let hits = executor.hit_offsets();
            let mut newly_found_offsets = Vec::new();
            {
                let mut global_offs = GLOBAL_SHARED_OFFSETS.lock().unwrap();
                for &off in hits {
                    if global_offs.insert(off) {
                        newly_found_offsets.push(off);
                    }
                }
            }
            let newly_found = newly_found_offsets.len();
            if newly_found > 0 {
                // 통계용으로 기록
                {
                    let mut new_offs = GLOBAL_NEW_OFFSETS.lock().unwrap();
                    new_offs.extend_from_slice(&newly_found_offsets);
                }
                GLOBAL_UNIQUE_OFFSETS.fetch_add(newly_found, Ordering::Relaxed);

                // 현재 testcase가 새 coverage 경로를 열었음 → local 폴더에 시드 저장
                if let Some(cid_ref) = state.corpus().current() {
                    let cid = *cid_ref;
                    if let Ok(tc) = state.corpus().get(cid) {
                        if let Some(input) = tc.borrow().input() {
                            let data = input.as_ref();
                            let mut hasher = AHasher::default();
                            data.hash(&mut hasher);
                            let fp = hasher.finish();

                            let file_path =
                                local_corpus_dir.join(format!("cov_{:016x}", fp));
                            if !file_path.exists() {
                                fs::write(&file_path, data)?;
                                println!(
                                    "[Thread {thread_id}] New coverage -> saved local seed: {:?}",
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

        // 일정 주기마다 로컬 ↔ 글로벌 큐 폴더 양방향 동기화
        let now = Instant::now();
        if now.duration_since(last_sync).as_secs() >= SYNC_INTERVAL {
            last_sync = now;

            // 1) 로컬 → 글로벌
            let newly_synced = sync_local_to_global(&local_corpus_dir, &global_queue_dir)?;
            if newly_synced > 0 {
                println!("[Thread {thread_id}] Synced {newly_synced} new seeds to global_queue.");
            }

            // 2) 글로벌 → 로컬
            let newly_synced2 = sync_global_to_local(&global_queue_dir, &local_corpus_dir)?;
            if newly_synced2 > 0 {
                println!("[Thread {thread_id}] Pulled {newly_synced2} seeds from global_queue.");

                // 동기화 후 새로 로컬 폴더에 추가된 시드들을 다시 state에 load
                state
                    .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[local_corpus_dir.clone()])
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            }
        }
    }
}

/// 메인
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::parse();

    let corpus_path = config.corpus_path.clone();
    let num_threads = config.forks;
    let global_queue_path = config.global_queue_path.clone();

    // 1) 메인에서 먼저 corpus 스캔
    let mut all_files = Vec::new();
    for entry in WalkDir::new(&corpus_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            all_files.push(entry.path().to_path_buf());
        }
    }
    println!("[Main] Found {} files in corpus", all_files.len());

    // 2) 일단 모든 파일을 글로벌 큐 폴더에 저장(중복 제외)
    fs::create_dir_all(&global_queue_path)?;
    {
        let mut added_global = 0;
        for file_path in &all_files {
            if let Some(fname) = file_path.file_name() {
                let global_target = global_queue_path.join(fname);
                if !global_target.exists() {
                    fs::copy(file_path, &global_target)?;
                    added_global += 1;
                }
            }
        }
        println!("[Main] Copied {added_global} corpus files into global_queue");
    }

    // 3) 쓰레드별 폴더를 만들고 global_queue를 로드
    let mut handles = Vec::new();
    for thread_id in 0..num_threads {
        let thread_input_dir = format!("thread_{thread_id}_input");
        let thread_crash_dir = format!("thread_{thread_id}_crashes");

        fs::create_dir_all(&thread_input_dir)?;
        fs::create_dir_all(&thread_crash_dir)?;

        // 초기에 글로벌 큐를 로컬 폴더로 한번 sync
        {
            let newly_synced = sync_global_to_local(&global_queue_path, Path::new(&thread_input_dir))?;
            println!("[Main] Thread {thread_id}: pulled {newly_synced} seeds from global_queue");
        }

        let param = ThreadParam {
            thread_id,
            local_corpus_dir: PathBuf::from(&thread_input_dir),
            crashes_dir: PathBuf::from(&thread_crash_dir),
            global_queue_dir: global_queue_path.clone(),
            tinyinst_args: {
                let mut tmp = vec![
                    "-instrument_module".to_string(),
                    config.tinyinst_module.clone(),
                    "-generate_unwind".to_string(),
                    "-cmp_coverage".to_string(),
                ];
                if let Some(extra) = config.tinyinst_extra.clone() {
                    tmp.push(extra);
                }
                tmp
            },
            target_args: {
                let mut tmp = vec![config.target.to_string_lossy().into_owned()];
                tmp.extend(config.target_args.clone());
                tmp
            },
            timeout: config.timeout,
        };

        let handle = thread::spawn(move || fuzz_thread_main(param));
        handles.push(handle);
    }

    // 4) 별도의 stats 스레드
    let stats_handle = thread::spawn(move || {
        let mut prev_execs = 0u64;
        let mut smoothed_speed = 0u64;
        const ALPHA: f64 = 0.2;

        loop {
            thread::sleep(Duration::from_secs(1));

            let execs = GLOBAL_EXECS.load(Ordering::Relaxed);
            let speed = execs.saturating_sub(prev_execs);
            prev_execs = execs;

            smoothed_speed =
                ((speed as f64) * ALPHA + (smoothed_speed as f64) * (1.0 - ALPHA)).round() as u64;

            let offsets_set_size = {
                let set = GLOBAL_SHARED_OFFSETS.lock().unwrap();
                set.len()
            };
            let max_cov = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);

            println!(
                "[Stats] coverage {:>8}, exec/s {:>10} (avg {:>10}), total_execs {:>12}, maxcov={}",
                offsets_set_size, speed, smoothed_speed, execs, max_cov
            );

            // 새로 발견된 오프셋 출력
            {
                let mut new_offs = GLOBAL_NEW_OFFSETS.lock().unwrap();
                if !new_offs.is_empty() {
                    new_offs.sort_unstable();
                    new_offs.dedup();
                    println!("[Stats] Newly discovered coverage offsets: {:?}", new_offs);
                    new_offs.clear();
                }
            }
        }
    });

    // 5) 워커 조인
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

    // 통계 스레드는 종료되지 않고 계속 돌지만,
    // 실제로는 Ctrl+C 시그널 등을 처리해서 중단하도록 하거나, join()을 호출해도 됩니다.
    // stats_handle.join().unwrap();

    Ok(())
}