use std::{
    collections::{BinaryHeap},
    cmp::Reverse,
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};
use std::collections::HashSet;
use clap::Parser;
use ahash::AHasher;
use libafl_bolts::HasLen;
/// simple conditional debug print
macro_rules! dbgln {
    ($($arg:tt)*) => {
        if DEBUG {
            println!("[{:?}] {}", Instant::now(), format_args!($($arg)*));
        }
    };
}

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
use walkdir::WalkDir;

/// 커버리지 맵 크기
const MAP_SIZE: usize = 65536;

/// 한 번 잡은 코퍼스 입력에 대해 몇 번 Mutate+Execute 할지
const BATCH: usize = 100;

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
    fingerprints: HashSet<u64>, // simple coverage hash
    stats: Vec<SampleStats>,   // per‑sample metadata
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
    /// 새 테스트케이스 추가
    fn push(&mut self, input: BytesInput, cov_hash: u64) {
        // 동일한 coverage fingerprint 가 이미 있으면 discard
        if self.fingerprints.contains(&cov_hash) {
            return;
        }
        let idx = self.all.len();
        self.all.push(input);
        self.discarded.push(false);
        self.stats.push(SampleStats::default());
        self.fingerprints.insert(cov_hash);
        // priority = 0 이면 높은 우선순위
        self.queue.push((Reverse(0), idx));
        if self.queue.len() > 1000 {
            self.queue.pop(); // drop lowest priority
        }
    }

    /// 작업 인덱스 하나 꺼내기 (priority 큐 흉내 – 앞에서 pop)
    fn pop_job(&mut self) -> Option<usize> {
        while let Some((_, idx)) = self.queue.pop() {
            if !self.discarded[idx] {
                return Some(idx);
            }
        }
        None
    }

    /// 작업 완료 후 재큐
    fn requeue(&mut self, idx: usize, prio: usize) {
        if !self.discarded[idx] {
            self.queue.push((Reverse(prio), idx));
        }
    }

    /// 해당 인덱스를 큐에서 제외
    fn discard(&mut self, idx: usize) {
        self.discarded[idx] = true;
        dbgln!("discard: idx={}", idx);
    }

    /// 반환: (총 샘플, discarded 수)
    fn stats(&self) -> (usize, usize) {
        (self.all.len(), self.discarded.iter().filter(|d| **d).count())
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
        ThreadContext { id, shared, local: Vec::new() }
    }

    /// Jackalope 의 SynchronizeAndGetJob
    fn synchronize_and_get_job(&mut self) -> Option<usize> {
        let t0 = Instant::now();
 
        // If we already have a previously‑fetched job, return it first.
        // (We no longer keep a separate local queue – 1 outstanding job per thread is enough.)
        // Instead, we’ll go back to the global queue every call.
        {
            let sh_read = self.shared.read().unwrap();
            if self.local.len() < sh_read.all.len() {
                let old = self.local.len();
                self.local.extend_from_slice(&sh_read.all[old..]);
            }
        }
 
        // Grab one job from the shared queue (write‑lock because we pop).
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
 
        dbgln!("Thread {} sync elapsed = {:?}", self.id, t0.elapsed());
        idx_opt
    }
}

const DEBUG: bool = true;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) CLI 파싱
    let config = Config::parse();

    // 2) 미리 꺼내 쓸 값들
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
        if let Some(x) = &config.tinyinst_extra { v.push(x.clone()); }
        v
    };
    let mut target_args = vec![config.target.to_string_lossy().into_owned()];
    target_args.extend(config.target_args.clone());

    // 3) 전역 SharedCorpus 초기화 (디스크에서 읽어서)
    let shared = Arc::new(RwLock::new(SharedCorpus::new()));
    {
        let mut sh = shared.write().unwrap();
        for entry in WalkDir::new(&corpus_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok()) {
            let path = entry.path().to_path_buf();
            if path.is_file() {
                if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                    if fname.starts_with('.') {
                        continue;
                    }
                }
                if let Ok(data) = fs::read(&path) {
                    let data_len = data.len();
                    // compute simple fingerprint based on file contents
                    let mut hasher = AHasher::default();
                    data.hash(&mut hasher);
                    let fp = hasher.finish();

                    let input = BytesInput::new(data);
                    sh.push(input, fp);
                    dbgln!("로드: {} ({} bytes)", path.display(), data_len);
                }
            }
        }
    }
    dbgln!(
        "초기 SharedCorpus 큐 크기: {}",
        shared.read().unwrap().all.len()
    );

    // 4) 스레드들 시작
    let mut handles = Vec::new();
    for thread_id in 0..num_threads {
        let shared       = shared.clone();
        let tinyinst_args = tinyinst_args.clone();
        let target_args  = target_args.clone();
        let timeout      = config.timeout;
        let _fuzz_iters  = config.fuzz_iterations;
        let corpus_path  = corpus_path.clone();
        let crashes_path = crashes_path.clone();

        handles.push(thread::spawn(move || {
            // ── libafl 기본 세팅 ──
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
                // dummy corpus; 실제 공유는 SharedCorpus 가 담당
                InMemoryOnDiskCorpus::<BytesInput>::new(corpus_path.clone()).unwrap(),
                OnDiskCorpus::<BytesInput>::new(crashes_path.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            ).unwrap();
            // seed the state corpus from the initial directory
            for _ in state.corpus().ids() { /* no-op */ }

            let scheduler = QueueScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let mut mgr = SimpleEventManager::new(MultiMonitor::new(|s| dbgln!("{}", s)));

            // 기존 시드들을 매니저에 전달하여 통계가 반영되도록
            for _ in state.corpus().ids() { /* no-op */ }

            let mut executor = TinyInstExecutor::builder()
                .tinyinst_args(tinyinst_args)
                .program_args(target_args)
                .timeout(Duration::from_millis(timeout))
                .coverage_ptr(cov_ptr)
                .build(tuple_list!(map_observer, time_observer)).unwrap();

            // ── Load initial corpus into LibAFL state and notify manager ──
            state
                .load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[corpus_path.clone()])
                .expect("Failed to load initial inputs");

            let mopt = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5).unwrap();
            let mut stages = tuple_list!(
                StdMutationalStage::new(mopt)
            );

            // ── Jackalope 스타일 런 루프 ──
            let mut ctx = ThreadContext::new(thread_id, shared);
            loop {
                if let Some(idx) = ctx.synchronize_and_get_job() {
                    // ── ensure this SharedCorpus input is in the LibAFL state corpus ──
                    let corpus_id = {
                        let input_bytes = ctx.local[idx].clone(); // BytesInput already
                        // check if already added via simple hash match; if not, add
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
                                // mgr.on_new_testcase(&state, &fuzzer, id).unwrap();
                                id
                            }
                        }
                    };
                    state.set_corpus_id(corpus_id).unwrap();

                    // compute a quick fingerprint of the input bytes so we can identify it in the logs
                    let mut dbg_hasher = AHasher::default();
                    ctx.local[idx].as_ref().hash(&mut dbg_hasher);
                    let input_fp = dbg_hasher.finish();
                    let input_len = ctx.local[idx].len();

                    dbgln!(
                        "[Thread {}] Fuzzing idx {} (len {:>6}, hash {:#016x})  ─ corpus_id = {:?}",
                        thread_id,
                        idx,
                        input_len,
                        input_fp,
                        corpus_id
                    );

                    let mut had_new_cov = false;
                    for _i in 0..BATCH {
                        let exec_before = *state.executions();
                        let cov_before_iter  = executor.hit_offsets().len();

                        if let Err(e) = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
                            eprintln!("Error during fuzzing: {:?}", e);
                            break;
                        }

                        let exec_after = *state.executions();
                        let cov_after_iter  = executor.hit_offsets().len();

                        if cov_after_iter > cov_before_iter {
                            had_new_cov = true;
                            dbgln!(
                                "[Thread {}] +cov: {} → {} (Δ {})  execs {}→{}",
                                thread_id,
                                cov_before_iter,
                                cov_after_iter,
                                cov_after_iter - cov_before_iter,
                                exec_before,
                                exec_after
                            );
                        } else {
                            dbgln!(
                                "[Thread {}] exec {}→{} (no new cov)",
                                thread_id,
                                exec_before,
                                exec_after
                            );
                        }
                    }
                    {
                    let mut sh = ctx.shared.write().unwrap();
                    // update metadata counters
                    let s = &mut sh.stats[idx];
                    s.num_runs += BATCH as u64;
                    if had_new_cov {
                        s.num_newcov += 1;
                    }
                    // TODO: num_crashes / num_hangs could be updated via observers

                    // schedule back into the queue
                    let prio = if had_new_cov { 0 } else { 3 };
                    sh.requeue(idx, prio);
                }
                    // detect newly added testcase in the corpus
                    // fuzz_one has already been called above, check if corpus grew
                    let after = state.corpus().count();
                    if after > 0 {
                        let new_id = after - 1;

                        // ---- clone bytes of newly‑added testcase while immutable borrow alive ----
                        let bytes_vec_opt = state
                            .corpus()
                            .get(CorpusId(new_id))
                            .ok()
                            .and_then(|cell| {
                                cell.borrow()
                                    .input()
                                    .as_ref()
                                    .map(|inp| inp.as_ref().to_vec())
                            });

                        if let Some(bytes_vec) = bytes_vec_opt {
                            // --------------------------------------------------------------------
                            // 1) compute a simple coverage fingerprint from the current hit offsets
                            // --------------------------------------------------------------------
                            let mut hasher = AHasher::default();
                            for off in executor.hit_offsets().iter() {
                                off.hash(&mut hasher);
                            }
                            let cov_fp = hasher.finish();

                            // --------------------------------------------------------------------
                            // 2) push the new sample into the shared corpus (if unique)
                            // --------------------------------------------------------------------
                            {
                                let mut sh = ctx.shared.write().unwrap();
                                sh.push(BytesInput::new(bytes_vec.clone()), cov_fp);
                                let (tot, disc) = sh.stats();
                                dbgln!(
                                    "[Thread {}] ▶ shared.push() – new total {}, discarded {}",
                                    thread_id,
                                    tot,
                                    disc
                                );
                            }

                            // --------------------------------------------------------------------
                            // 3) keep LibAFL state in sync: we already have the testcase at
                            //    CorpusId(new_id), so just tell the manager about it.
                            // --------------------------------------------------------------------
                        }
                    }
                } else {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }));
    }

    // 5) 조인
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
