use std::{
    collections::{BinaryHeap, HashSet},
    cmp::Reverse,
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{Arc, RwLock, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use clap::Parser;
use ahash::AHasher;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus, CorpusId, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{StdMOptMutator, havoc_mutations},
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{StdState, HasCorpus},
    state::HasExecutions,
    feedback_or_fast,
    Fuzzer, StdFuzzer,
};
use libafl::corpus::Corpus;
use libafl::corpus::HasCurrentCorpusId;
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_tinyinst::executor::TinyInstExecutor;
use libafl::executors::ExitKind;
use walkdir::WalkDir;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use once_cell::sync::Lazy;

/// simple conditional debug print (now unused)
macro_rules! dbgln {
    ($($arg:tt)*) => {
        // if DEBUG {
        //     println!("[{:?}] {}", Instant::now(), format_args!($($arg)*));
        // }
    };
}

/// 커버리지 맵 크기
const MAP_SIZE: usize = 65536;
/// TinyInst gives byte‑level offsets; each u64 word covers 8 bytes.
const MAP_BYTES: usize = MAP_SIZE * 8;

/// Global counters for periodic statistics
static GLOBAL_EXECS: AtomicU64 = AtomicU64::new(0);

/// (과거에 사용했던) offset별 카운팅 배열 - 지금은 실제 사용 안 함
static GLOBAL_COV: Lazy<Vec<AtomicU8>> =
    Lazy::new(|| (0..MAP_BYTES).map(|_| AtomicU8::new(0)).collect());

/// Maximum hit_offsets() length observed in any thread
static GLOBAL_MAX_THREAD_COV: AtomicUsize = AtomicUsize::new(0);

/// **신규로 발견된 offsets 총 개수** (전역 Set에서 완전히 처음 보는 offset만 카운팅)
static GLOBAL_UNIQUE_OFFSETS: AtomicUsize = AtomicUsize::new(0);

/// **전역으로 공유할 오프셋 Set** (디버깅+중복 여부 체크)
static GLOBAL_SHARED_OFFSETS: Lazy<Mutex<HashSet<u64>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// 한 번 잡은 코퍼스 입력에 대해 몇 번 Mutate+Execute 할지
const BATCH: usize = 100;

/// crash 횟수 임계값 (여기선 예시로 3회)
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

/// metadata counters we want to track for each input
#[derive(Default, Clone)]
struct SampleStats {
    num_runs: u64,
    num_crashes: u64,
    num_hangs: u64,
    num_newcov: u64,
}

/// Jackalope 스타일 전역 공유 코퍼스
struct SharedCorpus {
    all: Vec<BytesInput>,
    discarded: Vec<bool>,
    queue: BinaryHeap<(Reverse<usize>, usize)>, // (priority, idx)
    fingerprints: HashSet<u64>, // simple coverage hash (각 input의 해시)
    stats: Vec<SampleStats>,    // per‑sample metadata
}

impl SharedCorpus {
    fn new() -> Self {
        SharedCorpus {
            all: Vec::new(),
            discarded: Vec::new(),
            queue: BinaryHeap::new(),
            fingerprints: HashSet::new(),
            stats: Vec::new(),
        }
    }

    /// 새 테스트케이스 추가 (커버리지 fingerprint 중복 방지)
    fn push(&mut self, input: BytesInput, cov_hash: u64) {
        if self.fingerprints.contains(&cov_hash) {
            return;
        }
        let idx = self.all.len();
        self.all.push(input);
        self.discarded.push(false);
        self.stats.push(SampleStats::default());
        self.fingerprints.insert(cov_hash);
        self.queue.push((Reverse(0), idx));
        if self.queue.len() > 1000 {
            self.queue.pop();
        }
    }

    /// 작업 인덱스 하나 꺼내기
    fn pop_job(&mut self) -> Option<usize> {
        while let Some((_, idx)) = self.queue.pop() {
            if !self.discarded[idx] {
                return Some(idx);
            }
        }
        None
    }

    /// 작업 완료 후 재큐 (priority 낮추면 뒤로 밀림)
    fn requeue(&mut self, idx: usize, prio: usize) {
        if !self.discarded[idx] {
            self.queue.push((Reverse(prio), idx));
             dbgln!("requeue: idx={} prio={}  → queue_len={}", idx, prio, self.queue.len());
        }
    }

    /// 해당 인덱스를 큐에서 제외
    fn discard(&mut self, idx: usize) {
        self.discarded[idx] = true;
         dbgln!("discard: idx={}", idx);
    }

    /// 반환: (총 샘플 수, discarded 된 것 수)
    fn stats(&self) -> (usize, usize) {
        (
            self.all.len(),
            self.discarded.iter().filter(|d| **d).count(),
        )
    }
}

/// 스레드 로컬 컨텍스트: 로컬 캐시 + ID
struct ThreadContext {
    id: usize,
    shared: Arc<RwLock<SharedCorpus>>,
    local: Vec<BytesInput>,
}

impl ThreadContext {
    fn new(id: usize, shared: Arc<RwLock<SharedCorpus>>) -> Self {
        ThreadContext {
            id,
            shared,
            local: Vec::new(),
        }
    }

    /// Jackalope 의 "SynchronizeAndGetJob" – 전역 Corpus와 동기화 + 작업 1개 가져오기
    fn synchronize_and_get_job(&mut self) -> Option<usize> {
        let t0 = Instant::now();

        {
            let sh_read = self.shared.read().unwrap();
            if self.local.len() < sh_read.all.len() {
                let old = self.local.len();
                self.local.extend_from_slice(&sh_read.all[old..]);
            }
        }

        let idx_opt = {
            let mut sh = self.shared.write().unwrap();
            let idx = sh.pop_job();
             let (total, disc) = sh.stats();
             dbgln!(
                 "Thread {} sync: SharedCorpus stats – total {}, discarded {}, queue {}",
                 self.id,
                 total,
                 disc,
                 sh.queue.len()
             );
            idx
        };

        // dbgln!("Thread {} sync elapsed = {:?}", self.id, t0.elapsed());
        idx_opt
    }
}

// const DEBUG: bool = true;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();

    let corpus_path   = config.corpus_path.clone();
    let crashes_path  = config.crashes_path.clone();
    let num_threads   = config.forks;
    let _fuzz_iters   = config.fuzz_iterations;
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
                     dbgln!("로드: {} ({} bytes)", path.display(), data_len);
                }
            }
        }
    }
     dbgln!("초기 SharedCorpus 큐 크기: {}", shared.read().unwrap().all.len());

    let mut handles: Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>> = Vec::new();
    for thread_id in 0..num_threads {
        let shared       = shared.clone();
        let tinyinst_args = tinyinst_args.clone();
        let target_args  = target_args.clone();
        let timeout      = config.timeout;
        let _fuzz_iters  = config.fuzz_iterations;
        let corpus_path  = corpus_path.clone();
        let crashes_path = crashes_path.clone();

        handles.push(thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            // thread::sleep(Duration::from_secs((thread_id + 1) as u64));

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
                InMemoryOnDiskCorpus::<BytesInput>::new(corpus_path.clone()).unwrap(),
                OnDiskCorpus::<BytesInput>::new(crashes_path.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            ).unwrap();

            let scheduler = QueueScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            // Suppress multi-monitor debug prints by giving an empty closure
            
            
             let mut mgr = SimpleEventManager::new(MultiMonitor::new(|_s| {}));
            //////let mut mgr = SimpleEventManager::new(MultiMonitor::new(|x| println!("{x}")));

            let mut executor = TinyInstExecutor::builder()
                .tinyinst_args(tinyinst_args)
                .program_args(target_args)
                .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 1000000)
                .timeout(Duration::from_millis(timeout))
                .coverage_ptr(cov_ptr)
                .build(tuple_list!(map_observer, time_observer)).unwrap();

            match state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_path.clone()]) {
                Ok(_) => {}
                Err(err) => {
                    // executor.take_last_crash() 에 "Duplicate crash" 정보가 들어있다면
                    if let Some((crash_name, _is_unique, crash_count)) = executor.take_last_crash() {
                        eprintln!(
                            "[ViFuzz] 초기 로딩 중 중복 크래시 {:?} (count={}), 건너뜁니다",
                            crash_name, crash_count
                        );
                    } else {
                        // 기타 에러는 그대로 상위로 올려서 페닉
                        return Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>);
                    }
                }
            }

            let mopt = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5).unwrap();
            let mut stages = tuple_list!(StdMutationalStage::new(mopt));

            let mut ctx = ThreadContext::new(thread_id, shared);
            loop {
                if let Some(idx) = ctx.synchronize_and_get_job() {
                    let corpus_id = {
                        let input_bytes = ctx.local[idx].clone();
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
                    state.set_corpus_id(corpus_id).unwrap();

                    let mut had_new_cov = false;
                    let mut had_crash = false;
                    let mut had_hang = false;
                    for _i in 0..BATCH {
                        executor.reset_last_crash();

                        let exec_before = *state.executions();
                        // fuzz_one가 Err(“Duplicate crash…”)을 던질 수 있으므로 Result로 받습니다.
                        let fuzz_res = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr);
                        if let Err(err) = fuzz_res {
                            // executor에 기록된 마지막 crash 정보를 꺼내 보고
                            if let Some((crash_name, _is_unique, crash_count)) = executor.take_last_crash() {
                                eprintln!("[ViFuzz] Duplicate crash {:?} (count={}), discarding sample {}", crash_name, crash_count, idx);
                                let mut sh = ctx.shared.write().unwrap();
                                ////////// sh.discard(idx);
                                // 이 샘플은 더 돌리지 않도록 루프 탈출
                                break;
                            } else {
                                // 그 외 에러는 그대로 올려보냅니다.
                                return Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>);
                            }
                        }

                        // 정상 복귀한 경우에도 crash가 찍혔을 수 있으니 기존 로직 유지
                        if let Some((crash_name, is_unique, crash_count)) = executor.take_last_crash() {
                            println!("Crash name: {:?}, total count = {}", crash_name, crash_count);
                            had_crash = true;
                            if is_unique || crash_count > MAX_CRASHES {
                                println!("[ViFuzz] Discarding sample {} after crash", idx);
                                let mut sh = ctx.shared.write().unwrap();
                                sh.discard(idx);
                            }
                            break;
                        }

                        GLOBAL_EXECS.fetch_add((*state.executions() - exec_before) as u64, Ordering::Relaxed);

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
                            had_new_cov = true;
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

                            {
                                let mut sh = ctx.shared.write().unwrap();
                                sh.push(BytesInput::new(bytes_vec.clone()), sample_fp);
                                let (tot, disc) = sh.stats();
                                 dbgln!(
                                     "[Thread {}] ▶ shared.push() – new total {}, discarded {}",
                                     thread_id,
                                     tot,
                                     disc
                                 );
                            }
                        }
                    }
                } else {
// Comment out this debug message
                    println!("Thread {}: no jobs left, sleeping...", thread_id);
                    thread::sleep(Duration::from_millis(100));
                }
            }
            Ok(())
        }));
    }

    // Spawn stats reporter so that we see logs every second
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
                    "[ViFuzz] STATS: coverage {:>8}, \
                     samples {:>6} (discarded {:>6}), \
                     exec/s {:>10} (avg {:>10}), \
                     total_execs {:>12}",
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

    // 이제 fuzz 스레드들을 join 해서 메인 스레드가 종료되지 않게 막습니다.
    for handle in handles {
        let thr_res = handle.join()
            .map_err(|e| format!("thread panicked: {:?}", e))?;
        thr_res;
    }

    // (원한다면) stats thread 도 join 해 줄 수 있지만, 무한루프라서 생략하거나
    // stats_handle.join().unwrap();
    Ok(())
}