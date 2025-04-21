use std::{
    collections::{HashSet},
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{Arc, RwLock, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use clap::Parser;
use ahash::AHasher;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus, CorpusId, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{StdState, HasCorpus},
    state::HasExecutions,
    feedback_or_fast,
    Fuzzer, StdFuzzer,
};
use libafl::corpus::Corpus;
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_tinyinst::executor::TinyInstExecutor;
use libafl::executors::ExitKind;
use libafl::corpus::HasCurrentCorpusId;
use walkdir::WalkDir;
use rand::seq::SliceRandom;
use rand::thread_rng;

/// 커버리지 맵 크기
const MAP_SIZE: usize = 65536;
/// TinyInst gives byte‑level offsets; each u64 word covers 8 bytes.
const MAP_BYTES: usize = MAP_SIZE * 8;

/// 한 번 잡은 코퍼스 입력에 대해 몇 번 Mutate+Execute 할지
const BATCH: usize = 100;

/// crash 횟수 임계값
const MAX_CRASHES: usize = 3;

/// CLI 파싱용
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
struct Config {
    #[clap(long, value_parser, default_value = "../../corpus_discovered")]
    corpus_path: PathBuf,

    #[clap(long, value_parser, default_value = "./crashes")]
    crashes_path: PathBuf,

    #[clap(long, default_value_t = 1)]
    forks: usize,

    #[clap(long, default_value_t = 100)]
    fuzz_iterations: usize,

    #[clap(long, default_value_t = 4000)]
    timeout: u64,

    #[clap(long, default_value = "ImageIO")]
    tinyinst_module: String,

    #[clap(long)]
    tinyinst_extra: Option<String>,

    #[clap(long, value_parser)]
    target: PathBuf,

    #[clap(last = true)]
    target_args: Vec<String>,
}

/// 전역 counters for periodic statistics
static GLOBAL_EXECS: AtomicU64 = AtomicU64::new(0);

/// **신규로 발견된 offsets 총 개수** (전역 Set에서 완전히 처음 보는 offset만 카운팅)
static GLOBAL_UNIQUE_OFFSETS: AtomicUsize = AtomicUsize::new(0);

/// **전역으로 공유할 오프셋 Set** (디버깅+중복 여부 체크)
static GLOBAL_SHARED_OFFSETS: once_cell::sync::Lazy<Mutex<HashSet<u64>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashSet::new()));

/// Maximum unique coverage offsets so far
static GLOBAL_MAX_THREAD_COV: AtomicUsize = AtomicUsize::new(0);

/// (Optional) 입력 통계
#[derive(Default, Clone)]
struct SampleStats {
    num_runs: u64,
    num_crashes: u64,
    num_hangs: u64,
    num_newcov: u64,
}

/// 새로 만든 Round-Robin 형식의 공용 코퍼스
struct SharedCorpus {
    /// All inputs
    all: Vec<BytesInput>,
    /// Whether we've “removed” an input from the pool
    discarded: Vec<bool>,
    /// Simple coverage-hash set to avoid duplicates
    fingerprints: HashSet<u64>,
    /// Sample-level metadata (crash count, new coverage, etc.)
    stats: Vec<SampleStats>,

    /// Next index to pick in round-robin.  
    next_idx: AtomicUsize,
}

impl SharedCorpus {
    fn new() -> Self {
        Self {
            all: Vec::new(),
            discarded: Vec::new(),
            fingerprints: HashSet::new(),
            stats: Vec::new(),
            next_idx: AtomicUsize::new(0),
        }
    }

    /// 새 테스트케이스 추가
    fn push(&mut self, input: BytesInput, cov_hash: u64) {
        if self.fingerprints.contains(&cov_hash) {
            return;
        }
        self.fingerprints.insert(cov_hash);

        self.all.push(input);
        self.discarded.push(false);
        self.stats.push(SampleStats::default());
    }

    /// Round-robin으로 job 하나 꺼내기.  
    /// all.len() * 2 번 정도 시도 후, discard 아닌 것을 찾지 못하면 `None`.
    fn pop_job(&self) -> Option<usize> {
        let total = self.all.len();
        if total == 0 {
            return None;
        }
        for _attempts in 0..(total * 2) {
            let idx = self.next_idx.fetch_add(1, Ordering::Relaxed) % total;
            if !self.discarded[idx] {
                return Some(idx);
            }
        }
        None
    }

    /// discard
    fn discard(&mut self, idx: usize) {
        if idx < self.discarded.len() {
            self.discarded[idx] = true;
        }
    }

    fn stats(&self) -> (usize, usize) {
        let discarded_count = self.discarded.iter().filter(|x| **x).count();
        (self.all.len(), discarded_count)
    }
}

/// 스레드 로컬 컨텍스트
struct ThreadContext {
    id: usize,
    shared: Arc<RwLock<SharedCorpus>>,
    local_len: usize, // local cache: how many inputs we have so far
}

impl ThreadContext {
    fn new(id: usize, shared: Arc<RwLock<SharedCorpus>>) -> Self {
        Self {
            id,
            shared,
            local_len: 0,
        }
    }

    /// 새롭게 추가된 input이 있으면 local_len에 반영
    fn synchronize(&mut self) {
        let sh_read = self.shared.read().unwrap();
        if sh_read.all.len() > self.local_len {
            self.local_len = sh_read.all.len();
        }
    }

    /// round-robin pop
    fn get_job(&self) -> Option<usize> {
        let sh = self.shared.read().unwrap();
        sh.pop_job()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();

    let corpus_path   = config.corpus_path.clone();
    let crashes_path  = config.crashes_path.clone();
    let num_threads   = config.forks;
    let tinyinst_args = {
        let mut v = vec![
            "-instrument_module".into(),
            config.tinyinst_module.clone(),
            "-generate_unwind".into(),
        ];
        if let Some(x) = &config.tinyinst_extra {
            v.push(x.clone());
        }
        v
    };
    let mut target_args = vec![config.target.to_string_lossy().into_owned()];
    target_args.extend(config.target_args.clone());

    // Prepare shared corpus
    let shared = Arc::new(RwLock::new(SharedCorpus::new()));
    {
        let mut sh = shared.write().unwrap();
        for entry in WalkDir::new(&corpus_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path().to_path_buf();
            if path.is_file() {
                if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                    if fname.starts_with('.') {
                        continue;
                    }
                }
                if let Ok(data) = fs::read(&path) {
                    let mut hasher = AHasher::default();
                    data.hash(&mut hasher);
                    let fp = hasher.finish();
                    sh.push(BytesInput::new(data), fp);
                }
            }
        }
    }

    println!("[ViFuzz] Initial corpus count = {}", shared.read().unwrap().all.len());

    let mut handles: Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> = Vec::new();
    for thread_id in 0..num_threads {
        let shared       = shared.clone();
        let tinyinst_args = tinyinst_args.clone();
        let target_args  = target_args.clone();
        let timeout      = config.timeout;
        let corpus_dir   = corpus_path.clone();
        let crashes_dir  = crashes_path.clone();

        handles.push(thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut coverage_map = vec![0u64; MAP_SIZE];
            let cov_ptr: *mut Vec<u64> = &mut coverage_map as *mut Vec<u64>;
            let map_observer  = unsafe { StdMapObserver::new("cov", &mut coverage_map) };
            let time_observer = TimeObserver::new("time");

            let map_feedback = MaxMapFeedback::new(&map_observer);
            let mut feedback = feedback_or_fast!(map_feedback, TimeFeedback::new(&time_observer));
            let mut objective = CrashFeedback::new();

            let rand = StdRand::new();
            let mut state = StdState::new(
                rand.clone(),
                InMemoryOnDiskCorpus::<BytesInput>::new(corpus_dir.clone())?,
                OnDiskCorpus::<BytesInput>::new(crashes_dir.clone())?,
                &mut feedback,
                &mut objective,
            )?;

            let scheduler = QueueScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let mut mgr = SimpleEventManager::new(MultiMonitor::new(|_s| {}));

            let mut executor = TinyInstExecutor::builder()
                .tinyinst_args(tinyinst_args)
                .program_args(target_args)
                .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 1000000)
                .timeout(Duration::from_millis(timeout))
                .coverage_ptr(cov_ptr)
                .build(tuple_list!(map_observer, time_observer))?;

            // pre-load corpus
            let _ = state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_dir.clone()]);

            // ---- Havoc-only mutator (no MOpt) ----
            let havoc_mutator = StdScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(havoc_mutator));

            let mut ctx = ThreadContext::new(thread_id, shared);
            loop {
                ctx.synchronize();
                if let Some(idx) = ctx.get_job() {
                    // Ensure we have that sample in our local corpus
                    let input_bytes = {
                        let sh = ctx.shared.read().unwrap();
                        sh.all[idx].clone()
                    };

                    // Insert or find in local state corpus
                    let corpus_id = {
                        // Check if already in local corpus
                        let mut found = None;
                        for id in state.corpus().ids() {
                            if let Ok(cell) = state.corpus().get(id) {
                                if let Some(inp) = cell.borrow().input() {
                                    if inp.as_ref() == input_bytes.as_ref() {
                                        found = Some(id);
                                        break;
                                    }
                                }
                            }
                        }
                        match found {
                            Some(id) => id,
                            None => {
                                let id = state
                                    .corpus_mut()
                                    .add(Testcase::new(input_bytes.clone()))
                                    .unwrap();
                                id
                            }
                        }
                    };
                    state.set_corpus_id(corpus_id)?;

                    // Do BATCH fuzz calls
                    for _i in 0..BATCH {
                        executor.reset_last_crash();
                        let exec_before = *state.executions();

                        // fuzz_one
                        let fuzz_res = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr);
                        if let Err(err) = fuzz_res {
                            if let Some((crash_name, _is_unique, crash_count)) = executor.take_last_crash() {
                                eprintln!(
                                    "[Thread {}] Duplicate crash {:?} (count={}), discarding sample {}",
                                    thread_id, crash_name, crash_count, idx
                                );
                                let mut sh = ctx.shared.write().unwrap();
                                sh.discard(idx);
                                // Stop further fuzzing of this sample
                                break;
                            } else {
                                return Err(Box::new(err));
                            }
                        }

                        // Even if fuzz_one returned Ok, check if we got a new crash
                        if let Some((crash_name, is_unique, crash_count)) = executor.take_last_crash() {
                            println!("Crash name: {:?}, total count = {}", crash_name, crash_count);
                            if is_unique || crash_count > MAX_CRASHES {
                                println!(
                                    "[ViFuzz] Discarding sample {} after crash in thread {}",
                                    idx, thread_id
                                );
                                let mut sh = ctx.shared.write().unwrap();
                                sh.discard(idx);
                            }
                            // Move on to next sample
                            break;
                        }

                        GLOBAL_EXECS.fetch_add((*state.executions() - exec_before) as u64, Ordering::Relaxed);

                        // Coverage analysis
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

                        let len = GLOBAL_UNIQUE_OFFSETS.load(Ordering::Relaxed);
                        let mut prev = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed);
                        while len > prev
                            && GLOBAL_MAX_THREAD_COV
                                .compare_exchange_weak(
                                    prev,
                                    len,
                                    Ordering::Relaxed,
                                    Ordering::Relaxed
                                )
                                .is_err()
                        {
                            prev = GLOBAL_MAX_THREAD_COV.load(Ordering::Relaxed)
                        }
                    }

                    // Check if we appended a new testcase to local corpus
                    let after = state.corpus().count();
                    if after > 0 {
                        let new_id = after - 1;
                        let bytes_vec_opt = state
                            .corpus()
                            .get(CorpusId(new_id))
                            .ok()
                            .and_then(|cell| {
                                cell.borrow().input().as_ref().map(|inp| inp.as_ref().to_vec())
                            });
                        if let Some(bytes_vec) = bytes_vec_opt {
                            let mut hasher = AHasher::default();
                            bytes_vec.hash(&mut hasher);
                            let sample_fp = hasher.finish();

                            let mut sh = ctx.shared.write().unwrap();
                            sh.push(BytesInput::new(bytes_vec), sample_fp);
                        }
                    }

                } else {
                    // No jobs available
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }));
    }

    // Stats thread
    let stats_handle = {
        let shared_stats = shared.clone();
        thread::spawn(move || {
            let mut prev_execs = 0u64;
            let mut smoothed_speed = 0u64;
            const ALPHA: f64 = 0.2;
            loop {
                thread::sleep(Duration::from_secs(1));
                let execs = GLOBAL_EXECS.load(Ordering::Relaxed);
                let speed = execs - prev_execs;
                smoothed_speed = ((speed as f64) * ALPHA
                                  + (smoothed_speed as f64) * (1.0 - ALPHA))
                                 .round() as u64;
                prev_execs = execs;

                let (total_samples, discarded_samples) = {
                    let sh = shared_stats.read().unwrap();
                    sh.stats()
                };
                let offsets_set_size = {
                    let set = GLOBAL_SHARED_OFFSETS.lock().unwrap();
                    set.len()
                };

                println!(
                    "[ViFuzz] coverage {:>8}, samples {:>6} (discarded {:>6}), \
                     exec/s {:>10} (avg {:>10}), total_execs {:>12}",
                    offsets_set_size,
                    total_samples,
                    discarded_samples,
                    speed,
                    smoothed_speed,
                    execs
                );
            }
        })
    };

    // Wait for fuzz threads
    for handle in handles {
        let thr_res = handle.join()
            .map_err(|e| format!("thread panicked: {:?}", e))?;
        thr_res;
    }

    // stats_handle.join().unwrap(); // If you ever want to terminate

    Ok(())
}