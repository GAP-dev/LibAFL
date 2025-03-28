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

static mut COVERAGE: Vec<u64> = vec![];
static FUZZING: AtomicBool = AtomicBool::new(true);

#[cfg(any(target_vendor = "apple", windows, target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tinyinst_args = vec!["-instrument_module".to_string(), "ImageIO".to_string()];
    let args = vec![
        "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio"
            .to_string(),
        "-f".to_string(),
        "@@".to_string(),
    ];
    
    let coverage = OwnedMutPtr::Ptr(unsafe { &mut COVERAGE });
    let observer = ListObserver::new("cov", coverage);
    let mut feedback = ListFeedback::new(&observer);

    #[cfg(windows)]
    let mut shmem_provider = Win32ShMemProvider::new()?;
    #[cfg(unix)]
    let mut shmem_provider = UnixShMemProvider::new()?;

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

    let mut corpus = CachedOnDiskCorpus::new(corpus_path.clone(), 64)?;

    // 기존 corpus 폴더에서 데이터 불러오기
    if let Ok(entries) = fs::read_dir(&corpus_path) {
        for entry in entries.flatten() {
            if let Ok(data) = fs::read(entry.path()) {
                let input = BytesInput::new(data);
                corpus.add(Testcase::new(input))?;
            }
        }
    }
    
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes"))?;
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(|x| println!("{x}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(args)
        .timeout(Duration::from_millis(4000))
        .coverage_ptr(unsafe { &mut COVERAGE })
     //   .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 10000) //persistent mode 쓸라면 이거 주석해제
        .build(tuple_list!(ListObserver::new(
            "cov",
            unsafe { OwnedMutPtr::Ptr(&mut COVERAGE as *mut Vec<u64>) }
        )))?;

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    
    ///fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
    ///fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
    ///fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
    fuzzer
    .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    .expect("error in fuzzing loop");
    Ok(())
}