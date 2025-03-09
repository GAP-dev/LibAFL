use std::{path::PathBuf, time::Duration,fs};

use clap::Parser;
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



#[cfg(windows)]
use libafl_bolts::shmem::Win32ShMemProvider;
#[cfg(unix)]
use libafl_bolts::shmem::UnixShMemProvider; // 만약 Unix에서도 사용해야 한다면 적절히 수정하세요.

use libafl_bolts::{ownedref::OwnedMutPtr, rands::StdRand, tuples::tuple_list};
use libafl_tinyinst::executor::TinyInstExecutor;

// 전역 커버리지 변수
static mut COVERAGE: Vec<u64> = vec![];

/// AFL++ 스타일의 fuzzer CLI 인터페이스 예제
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// 타겟 환경변수 (예: DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib)
    #[arg(long)]
    target_env: Vec<String>,

    /// 이전 corpus에서 resume 모드로 실행 (기본값: false)
    #[arg(long)]
    resume: bool,

    /// 입력 corpus 디렉토리 (예: -in ./corpus_discovered)
    #[arg(short = 'i', long)]
    in_dir: PathBuf,

    /// 크래시/해결 corpus 디렉토리 (예: -out ./crashes)
    #[arg(short = 'o', long)]
    out_dir: PathBuf,

    /// delivery 디렉토리 (사용자가 원하는 경우 활용)
    #[arg(long)]
    delivery_dir: Option<PathBuf>,

    /// 타임아웃 (밀리초 단위, 기본값: 5000)
    #[arg(short = 't')]
    timeout: Option<u64>,

    /// (옵션) 추가 타임아웃 값 (예시: -T 10000)
    #[arg(short = 'T')]
    timeout1: Option<u64>,

    /// 스레드 수 (옵션, 내부 스레딩 사용 시)
    #[arg(long)]
    nthreads: Option<usize>,

    /// instrumentation 모듈 이름 (예: -instrument_module Bom)
    #[arg(long)]
    instrument_module: String,

    /// 타겟 프로그램 인자 개수 (예: -nargs 4)
    #[arg(long)]
    nargs: Option<usize>,

    /// persistent 모드 반복 횟수 (기본: 10000)
    #[arg(long, default_value = "10000")]
    iterations: usize,

    /// cmp_coverage 활성화 플래그
    #[arg(long)]
    cmp_coverage: bool,

    /// 최대 샘플 사이즈 (바이트 단위)
    #[arg(long)]
    max_sample_size: Option<usize>,

    /// unwind 정보 생성 활성화 플래그
    #[arg(long)]
    generate_unwind: bool,

    /// persistent 모드 사용 안 함 (AFL++의 -no-persistent와 유사)
    #[arg(long)]
    no_persistent: bool,

    /// "--" 이후에 오는 타겟 프로그램 및 인자 (예: /path/to/target @@)
    #[arg(last = true)]
    target_cmd: Vec<String>,
}

#[cfg(not(any(target_vendor = "apple", windows, target_os = "linux")))]
fn main() {}

#[cfg(any(target_vendor = "apple", windows, target_os = "linux"))]
fn main() {
    // 명령줄 인자 파싱
    let args = Args::parse();

    // 타겟 환경변수 설정
    for env in &args.target_env {
        if let Some((key, value)) = env.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    // delivery_dir가 지정된 경우 환경변수로 전달
    if let Some(ref delivery_dir) = args.delivery_dir {
        std::env::set_var("DELIVERY_DIR", delivery_dir);
    }

    // TinyInst에 전달할 인자 구성
    let tinyinst_args = vec![
        "-instrument_module".to_string(),
        args.instrument_module.clone(),
    ];

    // 타겟 커맨드 검증
    if args.target_cmd.is_empty() {
        eprintln!("Error: 타겟 프로그램 명령어가 제공되지 않았습니다.");
        std::process::exit(1);
    }




    // 타겟 프로그램 및 인자 (@@ 플레이스홀더 포함)
    let program_args = args.target_cmd.clone();
    ////println!("{:?} is program arg", program_args);


    println!("{:?} is program arg", program_args);
    println!("{:?} is in dir arg", args.in_dir);
    println!("{:?} is out dir arg", args.out_dir);
    // TinyInstExecutor 빌더 생성 (coverage_ptr에는 raw 포인터 전달)
    let mut builder = TinyInstExecutor::builder()
        
        .tinyinst_args(tinyinst_args)
        .program_args(program_args.join(" ").split_whitespace().map(String::from).collect())
        .timeout(Duration::from_millis(args.timeout.unwrap_or(5000)))
        .coverage_ptr(unsafe { &mut COVERAGE as *mut Vec<u64> });


    // persistent 모드 설정 (no_persistent 옵션에 따라)
    if !args.no_persistent {
        builder = builder.persistent("test".to_string(), "_fuzz".to_string(), 1, args.iterations);
    }

    // Executor 생성 시 ListObserver에는 OwnedMutPtr로 포인터를 감싸서 전달
    let mut executor = builder
        .build(tuple_list!(ListObserver::new(
            "cov",
            unsafe { OwnedMutPtr::Ptr(&mut COVERAGE as *mut Vec<u64>) }
        )))
        .unwrap();

    // Corpus, feedback, state 등 fuzzer 구성요소 초기화
////    let input = BytesInput::new(b"bad".to_vec());
    let rand = StdRand::new();

    /////let mut corpus = CachedOnDiskCorpus::new(args.in_dir, 64).expect("Corpus 생성 에러");

    let mut corpus = CachedOnDiskCorpus::new(args.in_dir.clone(), 64)
    .expect("Corpus 생성 에러");

    // 기존 corpus 파일을 불러오기
    let entries = fs::read_dir(&args.in_dir).expect("Corpus 디렉토리 읽기 실패");
    for entry in entries {
        let entry = entry.expect("Corpus 파일 읽기 실패");
        if let Ok(data) = fs::read(entry.path()) {
            let input = BytesInput::new(data);
            corpus.add(Testcase::new(input)).expect("Testcase 추가 에러");
        }
    }

    if !args.resume {
        let input = BytesInput::new(b"bad".to_vec());
        corpus.add(Testcase::new(input)).expect("Testcase 추가 에러");
    }
    let solutions = OnDiskCorpus::new(args.out_dir).expect("Crash corpus 생성 에러");

    let mut observer = ListObserver::new(
        "cov",
        unsafe { OwnedMutPtr::Ptr(&mut COVERAGE as *mut Vec<u64>) },
    );
    let mut feedback = ListFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
        .expect("State 생성 에러");

    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = SimpleMonitor::new(|x| println!("{x}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // fuzz 루프 시작
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Fuzzing 루프 에러");
}