use std::{fs, path::PathBuf, sync::atomic::AtomicBool, time::Duration, sync::Arc, sync::Mutex};

use libafl::state::{HasCorpus, HasSolutions};
use libafl::{
    corpus::{InMemoryCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, ListFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::ListObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
#[cfg(unix)]
use libafl_bolts::shmem::UnixShMemProvider;
#[cfg(windows)]
use libafl_bolts::shmem::Win32ShMemProvider;
use libafl_bolts::{
    ownedref::OwnedMutPtr, rands::StdRand, shmem::ShMemProvider, tuples::tuple_list,
};
use libafl_tinyinst::executor::TinyInstExecutor;

static mut COVERAGE: Vec<u64> = vec![];
static FUZZING: AtomicBool = AtomicBool::new(true);

// newtype wrapper for InMemoryCorpus to force Send
struct MyCorpus<T>(InMemoryCorpus<T>);

unsafe impl<T> Send for MyCorpus<T> {}

impl<T: Clone> Clone for MyCorpus<T> {
    fn clone(&self) -> Self {
        MyCorpus(self.0.clone())
    }
}

fn monitor_callback(x: &str) {
    println!("{x}");
}

#[cfg(any(target_vendor = "apple", windows, target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tinyinst_args = vec!["-instrument_module".to_string(), "ImageIO".to_string()];
    let args = vec![
        "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio".to_string(),
        "-f".to_string(),
        "@@".to_string(),
    ];
    
    let mut coverage = OwnedMutPtr::Ptr(unsafe { &mut COVERAGE });
    let observer = ListObserver::new("cov", coverage.clone());
    let mut feedback = ListFeedback::new(&observer);

    #[cfg(windows)]
    let _shmem_provider = Win32ShMemProvider::new()?;
    #[cfg(unix)]
    let _shmem_provider = UnixShMemProvider::new()?;

    let rand = StdRand::new();
    let corpus_path = PathBuf::from("../../corpus_discovered");

    // 숨김 파일 (.으로 시작하는 파일) 제거
    for entry in fs::read_dir(&corpus_path)? {
        if let Ok(entry) = entry {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|name| name.to_str()) {
                if filename.starts_with('.') {
                    fs::remove_file(path)?; // 숨김 파일 삭제
                }
            }
        }
    }

    // InMemoryCorpus 생성 후, 디스크의 기존 파일 불러오기
    let mut corpus: MyCorpus<BytesInput> = MyCorpus(InMemoryCorpus::new());
    if let Ok(entries) = fs::read_dir(&corpus_path) {
        for entry in entries.flatten() {
            if let Ok(data) = fs::read(entry.path()) {
                let input = BytesInput::new(data);
                corpus.0.add(Testcase::new(input))?;
            }
        }
    }
    if corpus.0.count() == 0 {
        corpus.0.add(Testcase::new(BytesInput::new(Vec::new())))?;
    }
    // 공유 corpus로 래핑 (Arc<Mutex<...>>)
    let shared_corpus = Arc::new(Mutex::new(corpus));

    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes"))?;
    let mut objective = CrashFeedback::new();
    // 메인 state는 공유 corpus의 복사본으로 생성 (내부 corpus 사용)
    let mut state = StdState::new(rand, (*shared_corpus.lock().unwrap()).clone().0, solutions, &mut feedback, &mut objective)?;
    let scheduler: RandScheduler<StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>> = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(monitor_callback as fn(&str));
    let mut mgr: SimpleEventManager<BytesInput, SimpleMonitor<fn(&str)>, StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>> = SimpleEventManager::new(monitor);
    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args.clone())
        .program_args(args.clone())
        .timeout(Duration::from_millis(4000))
        .coverage_ptr(coverage.as_mut())
        .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 10000)
        .build::<(ListObserver<u64>, ()), ()>(tuple_list!(ListObserver::new(
            "cov",
            unsafe { OwnedMutPtr::Ptr(&mut COVERAGE as *mut Vec<u64>) }
        )))?;

    use std::thread;

    let n = 10; // Number of threads

    let mut round: usize = 0;
    
    loop {
        println!("=== Fuzzing Round {round} ===");

        let mut handles = vec![];

        for _ in 0..n {
            let shared_corpus_clone = Arc::clone(&shared_corpus);
            let tinyinst_args = tinyinst_args.clone();
            let args = args.clone();

            let handle = thread::spawn(move || {
                // 각 스레드는 공유 corpus의 복사본을 사용하여 state를 생성
                let corpus_for_state = {
                    let guard = shared_corpus_clone.lock().unwrap();
                    guard.clone().0
                };
                let mut local_feedback = ListFeedback::new(&ListObserver::new("cov", OwnedMutPtr::Ptr(Box::leak(Box::new(Vec::<u64>::new())))));
                let mut local_objective = CrashFeedback::new();

                #[cfg(windows)]
                let _shmem_provider = Win32ShMemProvider::new().unwrap();
                #[cfg(unix)]
                let _shmem_provider = UnixShMemProvider::new().unwrap();

                let rand = StdRand::new();
                let mut local_state = StdState::new(rand, corpus_for_state, OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(), &mut local_feedback, &mut local_objective).unwrap();

                let scheduler = RandScheduler::new();
                let mut local_fuzzer = StdFuzzer::new(scheduler, local_feedback, local_objective);
                let local_monitor = SimpleMonitor::new(|x| println!("{x}"));
                let mut local_mgr = SimpleEventManager::new(local_monitor);

                let mut coverage = OwnedMutPtr::Ptr(Box::leak(Box::new(Vec::<u64>::new())));
                let observer = ListObserver::new("cov", coverage.clone());
                let mut local_executor = TinyInstExecutor::builder()
                    .tinyinst_args(tinyinst_args)
                    .program_args(args)
                    .timeout(Duration::from_millis(4000))
                    .coverage_ptr(coverage.as_mut())
                    .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 10000)
                    .build(tuple_list!(observer))
                    .unwrap();

                let mutator = StdScheduledMutator::new(havoc_mutations());
                let mut stages = tuple_list!(StdMutationalStage::new(mutator));

                local_fuzzer.fuzz_one(&mut stages, &mut local_executor, &mut local_state, &mut local_mgr).unwrap();

                // 업데이트: local_state의 corpus를 공유 corpus에 반영
                {
                    let mut guard = shared_corpus_clone.lock().unwrap();
                    *guard = MyCorpus(local_state.corpus().clone());
                }
                println!("Thread done. Corpus: {}, Solutions: {}, Coverage entries: {}",
                    local_state.corpus().count(), local_state.solutions().count(), coverage.as_ref().len());
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        println!("=== Round {round} Complete ===\n");

        round += 1;
    }

    println!("\n===== DEBUG INFO =====");
    println!("Corpus count: {}", state.corpus().count());
    println!("Solutions count: {}", state.solutions().count());
    println!("Coverage entries: {}", unsafe { COVERAGE.len() });
    println!("DEBUG TYPE INFO (compile-time known types):");
    println!("Stages: StdMutationalStage with multiple generic parameters");
    println!("Executor: TinyInstExecutor<S, SHM, OT> (generic, see source)");
    println!("State: StdState<R, C, S, O> (generic, see source)");
    println!("EventManager: SimpleEventManager<SimpleMonitor>");
    println!("======================\n");

    Ok(())
}