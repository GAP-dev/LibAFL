use std::{fs, path::PathBuf, sync::atomic::AtomicBool, time::Duration};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::{SimpleEventManager, EventConfig, launcher::Launcher},
    feedbacks::{CrashFeedback, ListFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::ListObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_bolts::shmem::{ServedShMemProvider, MmapShMemProvider, StdShMemProvider};
#[cfg(unix)]
use libafl_bolts::shmem::UnixShMemProvider;
#[cfg(windows)]
use libafl_bolts::shmem::Win32ShMemProvider;
use libafl_bolts::{
    core_affinity::Cores,
    ownedref::OwnedMutPtr, rands::StdRand, shmem::ShMemProvider, tuples::tuple_list,
};
use libafl_tinyinst::executor::TinyInstExecutor;

// 전역 커버리지 배열 (멀티프로세스 환경에서는 별도 관리 필요)
static mut COVERAGE: Vec<u64> = vec![];
static FUZZING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // env_logger를 초기화합니다.
    // env_logger는 기본적으로 로그를 stderr로 출력합니다.
    env_logger::init();

    // 실행 전에 이전에 생성된 서버 소켓 파일("./libafl_unix_shmem_server")이 있다면 삭제할 것!
    #[cfg(target_vendor = "apple")]
    {
        let socket_path = "./libafl_unix_shmem_server";
        if fs::metadata(socket_path).is_ok() {
            fs::remove_file(socket_path)?;
        }
    }

    // 공통 변수 설정
    let tinyinst_args = vec!["-instrument_module".to_string(), "ImageIO".to_string()];
    let args = vec![
        "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio".to_string(),
        "-f".to_string(),
        "@@".to_string(),
    ];

    // corpus 디렉토리 경로 (각 클라이언트에서 재사용)
    let corpus_path = PathBuf::from("../../corpus_discovered");
    // 숨김 파일(.으로 시작하는 파일) 제거
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

    // crashes(크래시 케이스) 저장 경로
    let crashes_path = PathBuf::from("./crashes");

    // Monitor 설정 (각 클라이언트에 전달)
   /// let monitor = SimpleMonitor::new(|x| println!("{x}"));
   let monitor = MultiMonitor::new(|s| println!("{s}"));
    // shmem_provider 초기화  
    // 여기서는 ServedShMemProvider를 MmapShMemProvider 기반으로 사용합니다.
   
   
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    ///////let mut shmem_provider = ServedShMemProvider::<MmapShMemProvider>::new()?;
    // 만약 POSIX 계열 UnixShMemProvider나 Windows 환경을 사용하려면 아래 주석을 해제하세요.
    // let mut shmem_provider = UnixShMemProvider::new()?;
    // let mut shmem_provider = Win32ShMemProvider::new()?;

    // 병렬 처리할 코어와 브로커 포트 지정
    let forks = 3; // 예시: 10개의 프로세스 사용
    let cores = Cores::from((0..forks).collect::<Vec<_>>());
    let broker_port = 1337; // 사용 가능한 포트 번호

    // Launcher를 통해 각 클라이언트 실행
    Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("MyFuzzer"))
        .monitor(monitor.clone())
        .run_client(|_state, _mgr, _client| {
            // 각 클라이언트에서 실행할 fuzzing 초기화 코드

            // 새로운 난수 생성기
            let rand = StdRand::new();

            // corpus 초기화 (디스크에 저장된 corpus 재로드)
            let mut corpus = CachedOnDiskCorpus::new(corpus_path.clone(), 64)?;
            if let Ok(entries) = fs::read_dir(&corpus_path) {
                for entry in entries.flatten() {
                    if let Ok(data) = fs::read(entry.path()) {
                        let input = BytesInput::new(data);
                        corpus.add(Testcase::new(input))?;
                    }
                }
            }
            // corpus가 비어 있으면 최소한 하나의 시드 입력 파일을 추가해야 합니다.
            if corpus.count() == 0 {
                return Err(libafl::Error::illegal_state(
                    "Corpus is empty. Please add at least one seed file.".to_string(),
                )
                .into());
            }

            // 크래시 저장 corpus
            let solutions = OnDiskCorpus::new(crashes_path.clone())?;
            let mut feedback = ListFeedback::new(&ListObserver::new(
                "cov",
                unsafe { OwnedMutPtr::Ptr(&mut COVERAGE) },
            ));
            let mut objective = CrashFeedback::new();
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

            let scheduler = RandScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let monitor = MultiMonitor::new(|s| println!("{s}"));
            ///let monitor = SimpleMonitor::new(|x| println!("{x}"));
            let mut event_manager = SimpleEventManager::new(monitor.clone());

            // Executor 초기화
            let tinyinst_args = vec!["-instrument_module".to_string(), "ImageIO".to_string()];
            let args = vec![
                "/Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio".to_string(),
                "-f".to_string(),
                "@@".to_string(),
            ];
            let mut executor = TinyInstExecutor::builder()
                .tinyinst_args(tinyinst_args.clone())
                .program_args(args.clone())
                .timeout(Duration::from_millis(4000))
                .persistent("test_imageio".to_string(), "_fuzz".to_string(), 1, 10000) //persistent mode 쓸라면 이거 주석해제
                .coverage_ptr(unsafe { &mut COVERAGE })
                .build(tuple_list!(ListObserver::new(
                    "cov",
                    unsafe { OwnedMutPtr::Ptr(&mut COVERAGE as *mut Vec<u64>) }
                )))?;

            let mutator = StdScheduledMutator::new(havoc_mutations());
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            // 실제 fuzzing 루프 실행
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut event_manager)
                .expect("error in fuzzing loop");

            Ok(())
        })

        

        .cores(&cores)
        .broker_port(broker_port)
        
        // stdout_file 옵션을 제거합니다.
        //.stdout_file(Some("./log"))
        .build()
        .launch::<BytesInput, ()>()?;

    Ok(())
}