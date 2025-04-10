use std::{fs, path::PathBuf, sync::atomic::AtomicBool, time::Duration};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
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

// COVERAGE는 전역 데이터로 사용. (실제 동시성 문제가 있다면 적절한 동기화 필요)
static mut COVERAGE: Vec<u64> = vec![];
static FUZZING: AtomicBool = AtomicBool::new(true);

#[cfg(any(target_vendor = "apple", windows, target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tinyinst_args = vec!["-instrument_module".to_string(), "ImageIO".to_string()];
    let args = vec![
        "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio".to_string(),
        "-f".to_string(),
        "@@".to_string(),
    ];
    
    let coverage = OwnedMutPtr::Ptr(unsafe { &mut COVERAGE });
    let observer = ListObserver::new("cov", coverage);
    
    // shmem_provider 사용하지 않으므로 _shmem_provider로 이름 변경
    #[cfg(windows)]
    let _shmem_provider = Win32ShMemProvider::new()?;
    #[cfg(unix)]
    let _shmem_provider = UnixShMemProvider::new()?;

    let corpus_path = PathBuf::from("../../corpus_discovered");

    // corpus 디렉토리 내 숨김 파일(.으로 시작하는 파일) 제거
    for entry in fs::read_dir(&corpus_path)? {
        if let Ok(entry) = entry {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|name| name.to_str()) {
                if filename.starts_with('.') {
                    fs::remove_file(path)?;
                }
            }
        }
    }

    let crashes_path = PathBuf::from("./crashes");

    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(args)
        .timeout(Duration::from_millis(4000))
        .coverage_ptr(unsafe { &mut COVERAGE })
        // persistent 모드를 사용하려면 아래 라인의 주석을 해제
        .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 10000)
        .build(tuple_list!(ListObserver::new(
            "cov",
            unsafe { OwnedMutPtr::Ptr(&mut COVERAGE as *mut Vec<u64>) }
        )))?;

    let mut mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let monitor = SimpleMonitor::new(|x| println!("{x}"));
    let mut mgr = SimpleEventManager::new(monitor);

    // 여러 iteration 동안 fuzzing을 수행하면서 매 iteration 후 corpus를 재로드함
    let iterations = 3;
    for i in 0..iterations {
        println!("Starting fuzzing iteration {}", i + 1);

        // corpus 디렉토리 내 숨김 파일(.으로 시작하는 파일) 제거
        for entry in fs::read_dir(&corpus_path)? {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.starts_with('.') {
                        fs::remove_file(path)?;
                    }
                }
            }
        }

        let mut corpus = CachedOnDiskCorpus::new(corpus_path.clone(), 64)?;
        if let Ok(entries) = fs::read_dir(&corpus_path) {
            for entry in entries.flatten() {
                if let Ok(data) = fs::read(entry.path()) {
                    let input = BytesInput::new(data);
                    corpus.add(Testcase::new(input))?;
                }
            }
        }
        let solutions = OnDiskCorpus::new(crashes_path.clone())?;

        let new_rand = StdRand::new();
        // 매 iteration마다 새로운 feedback과 objective를 생성하여 state와 fuzzer에 전달
        let mut feedback = ListFeedback::new(&observer);
        let mut objective = CrashFeedback::new();
        let mut state = StdState::new(new_rand, corpus, solutions, &mut feedback, &mut objective)?;
        let scheduler = RandScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        fuzzer
            .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 2)
            .expect("error in fuzz_loop_for");

        println!(
            "Iteration {} - Coverage data: {:?}",
            i + 1,
            executor.hit_offsets()
        );
    }
    Ok(())
}