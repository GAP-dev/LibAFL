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

use std::collections::HashSet;


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
            status = self.tinyinst.run();
            self.tinyinst
                .vec_coverage(self.coverage_ptr.as_mut().unwrap(), false);
        }
    
        // 🔥 디버깅: 커버리지 데이터 출력
     /*   unsafe {
            if let Some(coverage_data) = self.coverage_ptr.as_ref() {
                if coverage_data.is_empty() {
                    println!("[DEBUG] 커버리지 데이터 없음");
                } else {
                    println!("[DEBUG] 현재 커버리지 데이터: {:?}", coverage_data);
                }
            } else {
                println!("[DEBUG] coverage_ptr가 NULL입니다.");
            }
        }
     */
        
        // 🔥 커버리지 데이터 누적 저장
     /*  unsafe {
            if let Some(coverage_data) = self.coverage_ptr.as_ref() {
                if coverage_data.is_empty() {
                  //  println!("[DEBUG] 커버리지 데이터 없음");
                } else {
                    // 새로운 offset을 기존 set에 추가
                    for &addr in coverage_data.iter() {
                        self.hit_offsets.insert(addr);
                    }
                   // println!("[DEBUG] Hit Offsets: {:?}", self.hit_offsets);
                    println!("[DEBUG] 총 히트된 offset 개수: {}", self.hit_offsets.len());
                }
            } else {
                println!("[DEBUG] coverage_ptr가 NULL입니다.");
            }
        } */ 


        // 🔥 기존 `hit_offsets`과 비교하여 새로운 offset만 추가


        
        unsafe {
            if let Some(coverage_data) = self.coverage_ptr.as_ref() {
                if coverage_data.is_empty() {
                   // println!("[DEBUG] 커버리지 데이터 없음");
                } else {
        ////            let old_count = self.hit_offsets.len();
                    let mut new_hits = Vec::new();

                    for &addr in coverage_data.iter() {
                        if self.hit_offsets.insert(addr) { // 🔥 Set에 추가 시, 중복이면 false 반환
                            new_hits.push(addr); // 새로운 히트만 저장
                        }
                    }

     ////               let new_count = self.hit_offsets.len() - old_count;

                    if !new_hits.is_empty() {
          ////              println!("[DEBUG] 신규 발견된 Offset: {:?}", new_hits);
                    }
           ////         println!("[DEBUG] 이번 실행에서 추가된 offset 개수: {}", new_count);
           ////         println!("[DEBUG] 총 히트된 offset 개수: {}", self.hit_offsets.len());
                }
            } else {
          ////      println!("[DEBUG] coverage_ptr가 NULL입니다.");
            }
        }


        let mut retry_count = 0;
        let mut final_status = status;

        while matches!(final_status, RunResult::CRASH | RunResult::HANG) && retry_count < 3 {
   ////         println!("[DEBUG] RunResult::{:?} 발생, 재시도 중... ({}/{})", final_status, retry_count + 1, 4);
            retry_count += 1;
            unsafe {
                final_status = self.tinyinst.run();
                self.tinyinst
                    .vec_coverage(self.coverage_ptr.as_mut().unwrap(), false);
            }
        }

        match final_status {
            RunResult::CRASH | RunResult::HANG if retry_count == 3 => {
     /////           println!("[DEBUG] 4회 모두 CRASH/HANG 발생, Crash로 처리");
                Ok(ExitKind::Crash)
            }
            RunResult::CRASH | RunResult::HANG => {
    /////            println!("[DEBUG] 재시도 도중 상태 변경됨, Crash 아님");
                Ok(ExitKind::Ok)
            }
            RunResult::OK => Ok(ExitKind::Ok),
            RunResult::OTHER_ERROR => Err(Error::unknown(
                "Tinyinst RunResult is other error".to_string(),
            )),
            _ => Err(Error::unknown("Tinyinst RunResult is unknown".to_string())),
        }
        
    }
    
}


impl<S, SHM, OT> TinyInstExecutor<S, SHM, OT> {
    /// 반환: 누적된 hit offset 집합에 대한 참조
    pub fn hit_offsets(&self) -> &HashSet<u64> {
        &self.hit_offsets
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
