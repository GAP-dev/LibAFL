use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ptr,
    time::Duration,
};

use libafl::{
    Error,
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    state::HasExecutions,
};
use libafl_bolts::{
    AsSlice, AsSliceMut,
    fs::{INPUTFILE_STD, InputFile},
    shmem::{NopShMem, NopShMemProvider, ShMem, ShMemProvider},
    tuples::RefIndexable,
};
use tinyinst::tinyinst::{TinyInst, litecov::RunResult};

use std::{collections::HashMap,collections::HashSet, sync::Mutex};
use once_cell::sync::Lazy;

// crash 이름별 카운트를 저장하는 전역 맵
static UNIQUE_CRASHES: Lazy<Mutex<HashMap<String, usize>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// [`TinyInst`](https://github.com/googleprojectzero/TinyInst) executor
pub struct TinyInstExecutor<S, SHM, OT> {
    tinyinst: TinyInst,
    coverage_ptr: *mut Vec<u64>,
    timeout: Duration,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    map: Option<SHM>,
    hit_offsets: HashSet<u64>,
    last_crash: Option<(String, bool)>,  // (crash_name, is_unique)
    last_exit_kind: Option<ExitKind>,
}

impl TinyInstExecutor<(), NopShMem, ()> {
    /// Create a builder for [`TinyInstExecutor`]
    #[must_use]
    pub fn builder<'a>() -> TinyInstExecutorBuilder<'a, NopShMemProvider> {
        TinyInstExecutorBuilder::new()
    }
}

impl<S, SHM, OT> Debug for TinyInstExecutor<S, SHM, OT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("TinyInstExecutor")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<EM, I, OT, S, SHM, Z> Executor<EM, I, S, Z> for TinyInstExecutor<S, SHM, OT>
where
    S: HasExecutions,
    I: HasTargetBytes,
    SHM: ShMem,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        match &self.map {
            Some(_) => {
                let shmem = unsafe { self.map.as_mut().unwrap_unchecked() };
                let target_bytes = input.target_bytes();
                let size = target_bytes.as_slice().len();
                let size_in_bytes = size.to_ne_bytes();
    
                shmem.as_slice_mut()[..SHMEM_FUZZ_HDR_SIZE]
                    .copy_from_slice(&size_in_bytes[..SHMEM_FUZZ_HDR_SIZE]);
                shmem.as_slice_mut()[SHMEM_FUZZ_HDR_SIZE..(SHMEM_FUZZ_HDR_SIZE + size)]
                    .copy_from_slice(target_bytes.as_slice());
            }
            None => {
                self.cur_input.write_buf(input.target_bytes().as_slice())?;
            }
        }
        
        
        #[expect(unused_assignments)]
        let mut status = RunResult::OK;

        unsafe {
            // 1) 첫 실행
            status = self.tinyinst.run();
            // 커버리지를 vec<u64> 형태로 가져오기
            self.tinyinst
                .vec_coverage(self.coverage_ptr.as_mut().unwrap(), false);

            // coverage_ptr에서 offsets를 꺼내 hit_offsets에 쌓기
            let cov_vec = self.coverage_ptr.as_mut().unwrap();
            self.hit_offsets.extend(cov_vec.drain(..));
            cov_vec.clear();
        }

        // 2) CRASH/HANG이면 최대 3번 재시도(플레이키 문제 등)
        let mut retry_count = 0;
        let mut final_status = status;
        while matches!(final_status, RunResult::CRASH | RunResult::HANG) && retry_count < 3 {
            retry_count += 1;
            unsafe {
                final_status = self.tinyinst.run();
                self.tinyinst
                    .vec_coverage(self.coverage_ptr.as_mut().unwrap(), false);
            }
        }

        // 3) 최종적으로 CRASH/HANG이라면, CrashName 받아 중복 체크
        if matches!(final_status, RunResult::CRASH | RunResult::HANG) {
            // tinyinst-rs 바인딩에 따라 "get_crash_name()"을 노출했다고 가정
            // 없다면 C++ side bridge에 GetCrashName() 추가 후 가져와야 함.
            if let Some(crash_name) = unsafe { self.tinyinst.get_crash_name() } {
                let mut map = UNIQUE_CRASHES.lock().unwrap();
                let count = map.entry(crash_name.clone()).or_insert(0);
                *count += 1;
                let is_unique = *count == 1;
                // main 에 전달하기 위해 저장
                self.last_crash = Some((crash_name.clone(), is_unique));
                if is_unique {
                    // 유니크 크래시: 첫 발견
                    // TODO: crash corpus에 저장, 로깅 등
                    eprintln!("[*] New unique crash: {crash_name}");
                } else {
                    // 중복 크래시
                    eprintln!("[*] Duplicate crash: {crash_name} (count={})", *count);
                }
            }
        }

        // 4) 최종 상태에 따라 ExitKind 결정
        let exit_kind = match final_status {
            // 재시도 끝에 여전히 CRASH이면 실제 Crash 처리
            RunResult::CRASH if retry_count == 3 => ExitKind::Crash,
            // 재시도 끝에 여전히 HANG이면 Hang으로 간주하여 Timeout 처리
            RunResult::HANG if retry_count == 3 => ExitKind::Timeout,
            // 재시도 중에 성공하거나 (즉, OK를 반환했거나),
            // Crash/Hang이지만 retry_count가 3 미만이면 "플레이키"로 간주하여 Ok 처리
            RunResult::CRASH | RunResult::HANG => ExitKind::Ok,
            RunResult::OK => ExitKind::Ok,
            RunResult::OTHER_ERROR => {
                return Err(Error::unknown(
                    "Tinyinst RunResult is other error".to_string(),
                ));
            },
            _ => {
                return Err(Error::unknown(
                    "Tinyinst RunResult is unknown".to_string(),
                ));
            },
        };

        // 새로 추가된 부분: 마지막 ExitKind 기록
        self.last_exit_kind = Some(exit_kind);

        // 반환
        Ok(exit_kind)
    }
}



impl<S, SHM, OT> TinyInstExecutor<S, SHM, OT> {
    /// 반환: 누적된 hit offset 집합에 대한 참조
    pub fn hit_offsets(&self) -> &HashSet<u64> {
        &self.hit_offsets
    }
    //executor.hit_offsets_mut().clear();구현해
    /// Clear the hit offsets
    pub fn hit_offsets_mut(&mut self) -> &mut HashSet<u64> {
        &mut self.hit_offsets
    }
    /// clear the hit offsets

    /// Baseline (ignore) whatever coverage TinyInst has recorded up to now.
    /// This mimics Jackalope's incremental‑coverage strategy.
    pub fn ignore_current_coverage(&mut self) {
        let mut _scratch: Vec<u64> = Vec::new();
        self.tinyinst.vec_coverage(&mut _scratch, true);
    }

    /// run_target 에서 저장된 마지막 crash name 을 꺼냅니다
    pub fn take_last_crash(&mut self) -> Option<(String, bool)> {
        self.last_crash.take()
    }

    #[allow(missing_docs)]
    pub fn reset_last_crash(&mut self) {
        self.last_crash = None;
    }

    /// run_target 이 마지막으로 반환한 ExitKind 를 가져옵니다.
    pub fn last_exit_kind(&self) -> Option<ExitKind> {
        self.last_exit_kind
    }
}


/// Builder for `TinyInstExecutor`
#[derive(Debug)]
pub struct TinyInstExecutorBuilder<'a, SP> {
    tinyinst_args: Vec<String>,
    program_args: Vec<String>,
    timeout: Duration,
    coverage_ptr: *mut Vec<u64>,
    shmem_provider: Option<&'a mut SP>,
}

const MAX_FILE: usize = 1024 * 1024;
const SHMEM_FUZZ_HDR_SIZE: usize = 4;

impl Default for TinyInstExecutorBuilder<'_, NopShMemProvider> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TinyInstExecutorBuilder<'a, NopShMemProvider> {
    /// Constructor
    #[must_use]
    pub fn new() -> TinyInstExecutorBuilder<'a, NopShMemProvider> {
        Self {
            tinyinst_args: vec![],
            program_args: vec![],
            timeout: Duration::new(3, 0),
            shmem_provider: None,
            coverage_ptr: ptr::null_mut(),
        }
    }

    /// Use this to enable shmem testcase passing.
    #[must_use]
    pub fn shmem_provider<SP>(self, shmem_provider: &'a mut SP) -> TinyInstExecutorBuilder<'a, SP> {
        TinyInstExecutorBuilder {
            tinyinst_args: self.tinyinst_args,
            program_args: self.program_args,
            timeout: self.timeout,
            shmem_provider: Some(shmem_provider),
            coverage_ptr: ptr::null_mut(),
        }
    }
}

impl<SP> TinyInstExecutorBuilder<'_, SP>
where
    SP: ShMemProvider,
{
    /// Argument for tinyinst instrumentation
    #[must_use]
    pub fn tinyinst_arg(mut self, arg: String) -> Self {
        self.tinyinst_args.push(arg);
        self
    }

    /// Arguments for tinyinst instrumentation
    #[must_use]
    pub fn tinyinst_args(mut self, args: Vec<String>) -> Self {
        for arg in args {
            self.tinyinst_args.push(arg);
        }
        self
    }

    /// The module to instrument.
    #[must_use]
    pub fn instrument_module(mut self, module: Vec<String>) -> Self {
        for modname in module {
            self.tinyinst_args.push("-instrument_module".to_string());
            self.tinyinst_args.push(modname);
        }
        self
    }

    /// Use shmem
    #[must_use]
    pub fn use_shmem(mut self) -> Self {
        self.tinyinst_args.push("-delivery".to_string());
        self.tinyinst_args.push("shmem".to_string());
        self
    }

    /// Persistent mode
    #[must_use]
    pub fn persistent(
        mut self,
        target_module: String,
        target_method: String,
        nargs: usize,
        iterations: usize,
    ) -> Self {
        self.tinyinst_args.push("-target_module".to_string());
        self.tinyinst_args.push(target_module);

        self.tinyinst_args.push("-target_method".to_string());
        self.tinyinst_args.push(target_method);

        self.tinyinst_args.push("-nargs".to_string());
        self.tinyinst_args.push(nargs.to_string());

        self.tinyinst_args.push("-iterations".to_string());
        self.tinyinst_args.push(iterations.to_string());

        self.tinyinst_args.push("-persist".to_string());
        self.tinyinst_args.push("-loop".to_string());
        self
    }

    /// Program arg
    #[must_use]
    pub fn program_arg(mut self, arg: String) -> Self {
        self.program_args.push(arg);
        self
    }

    /// Program args
    #[must_use]
    pub fn program_args(mut self, args: Vec<String>) -> Self {
        for arg in args {
            self.program_args.push(arg);
        }
        self
    }

    /// Set timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the pointer to the coverage vec used to observer the execution.
    ///
    /// # Safety
    /// The coverage vec pointer must point to a valid vec and outlive the time the [`TinyInstExecutor`] is alive.
    /// The map will be dereferenced and borrowed mutably during execution. This may not happen concurrently.
    #[must_use]
    pub fn coverage_ptr(mut self, coverage_ptr: *mut Vec<u64>) -> Self {
        self.coverage_ptr = coverage_ptr;
        self
    }

    /// Build [`TinyInst`](https://github.com/googleprojectzero/TinyInst) executor
    pub fn build<OT, S>(
        &mut self,
        observers: OT,
    ) -> Result<TinyInstExecutor<S, SP::ShMem, OT>, Error> {
        if self.coverage_ptr.is_null() {
            return Err(Error::illegal_argument("Coverage pointer may not be null."));
        }
        let (map, shmem_id) = match &mut self.shmem_provider {
            Some(provider) => {
                // setup shared memory
                let mut shmem = provider.new_shmem(MAX_FILE + SHMEM_FUZZ_HDR_SIZE)?;
                let shmem_id = shmem.id();
                // log::trace!("{:#?}", shmem.id());
                // shmem.write_to_env("__TINY_SHM_FUZZ_ID")?;

                let size_in_bytes = (MAX_FILE + SHMEM_FUZZ_HDR_SIZE).to_ne_bytes();
                shmem.as_slice_mut()[..4].clone_from_slice(&size_in_bytes[..4]);

                (Some(shmem), Some(shmem_id))
            }
            None => (None, None),
        };

        let mut has_input = false;
        let program_args: Vec<String> = self
            .program_args
            .clone()
            .into_iter()
            .map(|arg| {
                if arg == "@@" {
                    has_input = true;
                    match shmem_id {
                        Some(shmem_name) => shmem_name.to_string(),
                        None => INPUTFILE_STD.to_string(),
                    }
                } else {
                    arg
                }
            })
            .collect();

        if !has_input {
            return Err(Error::unknown(
                "No input file or shmem provided".to_string(),
            ));
        }
        log::info!("tinyinst args: {:#?}", &self.tinyinst_args);

        let cur_input = InputFile::create(INPUTFILE_STD).expect("Unable to create cur_file");

        let tinyinst = unsafe {
            TinyInst::new(
                &self.tinyinst_args,
                &program_args,
                self.timeout.as_millis() as u32,
            )
        };

        Ok(TinyInstExecutor {
            tinyinst,
            coverage_ptr: self.coverage_ptr,
            timeout: self.timeout,
            observers,
            phantom: PhantomData,
            cur_input,
            map,
            hit_offsets: HashSet::new(),
            last_crash: None,
            last_exit_kind: None,
        })
    }
}

impl<S, SHM, OT> HasObservers for TinyInstExecutor<S, SHM, OT> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
