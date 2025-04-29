//! custom_mutations.rs
//! 
//! 예시: C++ 스타일의 mutation 로직 (ByteFlip, Arithmetic, BlockInsert 등)을 
//! Rust + LibAFL에서 구현하는 샘플 코드.
//!
//! 이 예시는 다음과 같은 Mutation 로직을 포함합니다:
//! - ByteFlipMutator
//! - ArithmeticMutator
//! - AppendMutator
//! - BlockInsertMutator
//! - BlockFlipMutator
//! - BlockDuplicateMutator
//! - InterestingValueMutator
//! - SpliceMutator
//! 
//! 마지막에 WeightedUnionMutator 로 여러 mutation 을 확률적으로 조합하는
//! `create_custom_mutation_suite()` 함수를 제공합니다.
//!
//! 실제 프로덕션에서는 세부 로직(특히 BlockFlip, Splice 등)을
//! 요구사항에 맞춰 재정비해야 합니다.
//!
//! 이 코드는 `Vec<u8>`(raw byte buffer) 입력에 적용된다고 가정합니다.

use core::cmp::{min, max};
use alloc::vec::Vec;
use alloc::boxed::Box;
use libafl::{
    mutators::{MutationResult, Mutator, ScheduledMutator},
    state::{HasRand},
};
use libafl_bolts::rands::Rand; // for random generation
use libafl_bolts::AsSlice;

/* ---------------------------------------------------------------------------
 * 1) ByteFlipMutator
 *    - 랜덤한 위치의 비트를 flip(토글)하는 예시
 * -------------------------------------------------------------------------*/
#[derive(Debug, Default)]
pub struct ByteFlipMutator;

impl ByteFlipMutator {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Mutator<S, Vec<u8>> for ByteFlipMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        if input.is_empty() {
            return MutationResult::Skipped;
        }
        // 랜덤 위치 한 곳의 비트 1개를 뒤집는다
        let idx = state.rand_mut().below(input.len() as u64) as usize;
        let bit = state.rand_mut().below(8) as u8;
        input[idx] ^= 1 << bit;

        MutationResult::Mutated
    }

    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 2) ArithmeticMutator
 *    - 바이트/워드/드워드/큐워드 등 임의 크기 정수에 ±랜덤값을 더하는 식으로
 *      단순 산술조작.
 * -------------------------------------------------------------------------*/
#[derive(Debug, Default)]
pub struct ArithmeticMutator;

impl ArithmeticMutator {
    pub fn new() -> Self {
        Self
    }

    /// 값을 엔디안 플립하는 보조 함수 (ex: 0x1234 -> 0x3412)
    fn flip_endian<T: Copy + Into<u64> + From<u64>>(val: T, size: usize) -> T {
        let mut bytes = [0u8; 8];
        let v64 = val.into();
        for i in 0..size {
            bytes[i] = (v64 >> (8 * i)) as u8;
        }
        let mut flipped = 0u64;
        for i in 0..size {
            flipped |= (bytes[i] as u64) << (8 * (size - 1 - i));
        }
        T::from(flipped)
    }

    /// 산술 조작을 수행. 크기가 1/2/4/8 중 하나
    fn mutate_arithmetic<S: HasRand>(&self, state: &mut S, input: &mut [u8], size: usize) {
        if input.len() < size {
            return; // 사이즈가 충분치 않으면 skip
        }
        let pos = state.rand_mut().below((input.len() - size + 1) as u64) as usize;
        let flip_endian = state.rand_mut().below(2) == 0;

        let mut val = 0u64;
        // size 만큼 바이트 -> val
        for i in 0..size {
            val |= (input[pos + i] as u64) << (8 * i);
        }

        if flip_endian {
            // val을 size 바이트 크기로 flip
            let typed = Self::flip_endian(val, size);
            val = typed.into();
        }

        // [-256, +256] 사이값
        let delta = (state.rand_mut().below(513) as i64) - 256;
        let new_val = (val as i64).wrapping_add(delta);

        let new_val64 = new_val as u64;
        // 다시 flip_endian
        let final_val = if flip_endian {
            Self::flip_endian(new_val64, size)
        } else {
            new_val64
        };

        // 바이트 배열에 반영
        for i in 0..size {
            input[pos + i] = ((final_val >> (8 * i)) & 0xFF) as u8;
        }
    }
}

impl<S> Mutator<S, Vec<u8>> for ArithmeticMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        if input.is_empty() {
            return MutationResult::Skipped;
        }
        // 1/2/4/8 중 랜덤으로 하나 고름
        let possible_sizes = [1, 2, 4, 8];
        let size = *possible_sizes
            .get(state.rand_mut().below(possible_sizes.len() as u64) as usize)
            .unwrap();
        self.mutate_arithmetic(state, input.as_mut_slice(), size);

        MutationResult::Mutated
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 3) AppendMutator
 *    - 난수 크기(1..max_append) 만큼 input 뒤에 바이트를 추가
 * -------------------------------------------------------------------------*/
#[derive(Debug)]
pub struct AppendMutator {
    min_append: usize,
    max_append: usize,
}

impl AppendMutator {
    pub fn new(min_append: usize, max_append: usize) -> Self {
        Self { min_append, max_append }
    }
}

impl<S> Mutator<S, Vec<u8>> for AppendMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        let old_len = input.len();
        let len_range = self.max_append - self.min_append + 1;
        let to_append = self.min_append + (state.rand_mut().below(len_range as u64) as usize);

        // 간단히 최대 크기 제한 (원본 C++에선 Sample::max_size가 있었지만 여긴 생략)
        // 원하는 경우 max_size를 설정해도 됨
        for _ in 0..to_append {
            let byte = state.rand_mut().below(256) as u8;
            input.push(byte);
        }

        if input.len() != old_len {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        }
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 4) BlockInsertMutator
 *    - input 내부 임의 위치에 일정 크기(1..max) 블록을 삽입
 * -------------------------------------------------------------------------*/
#[derive(Debug)]
pub struct BlockInsertMutator {
    min_insert: usize,
    max_insert: usize,
}

impl BlockInsertMutator {
    pub fn new(min_insert: usize, max_insert: usize) -> Self {
        Self { min_insert, max_insert }
    }
}

impl<S> Mutator<S, Vec<u8>> for BlockInsertMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        let old_len = input.len();
        if old_len == 0 {
            return MutationResult::Skipped;
        }
        let len_range = self.max_insert - self.min_insert + 1;
        let block_size = self.min_insert + (state.rand_mut().below(len_range as u64) as usize);

        let pos = state.rand_mut().below(old_len as u64) as usize;
        let mut block = Vec::with_capacity(block_size);
        for _ in 0..block_size {
            block.push(state.rand_mut().below(256) as u8);
        }

        // 삽입
        input.splice(pos..pos, block);

        if input.len() > old_len {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        }
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 5) BlockFlipMutator
 *    - 지정된 범위의 블록 크기 내에서 무작위 블록 하나를 골라, 그 내부를
 *      uniform 하게(전부 같은 byte) 혹은 random byte들로 덮어쓰는 버전
 * -------------------------------------------------------------------------*/
#[derive(Debug)]
pub struct BlockFlipMutator {
    min_block_size: usize,
    max_block_size: usize,
    uniform: bool, // 블록 전체를 동일 byte로 덮을지 여부
}

impl BlockFlipMutator {
    pub fn new(min_block_size: usize, max_block_size: usize, uniform: bool) -> Self {
        Self {
            min_block_size,
            max_block_size,
            uniform,
        }
    }
}

impl<S> Mutator<S, Vec<u8>> for BlockFlipMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        if input.is_empty() {
            return MutationResult::Skipped;
        }
        let size = input.len();
        let min_b = min(self.min_block_size, size);
        let max_b = min(self.max_block_size, size);

        if max_b < 1 {
            return MutationResult::Skipped;
        }

        let block_size = min_b + (state.rand_mut().below((max_b - min_b + 1) as u64) as usize);
        let block_start = state.rand_mut().below((size - block_size + 1) as u64) as usize;

        if self.uniform {
            // 블록 전체를 동일한 랜덤 바이트로 덮어쓴다
            let fill_byte = state.rand_mut().below(256) as u8;
            for i in 0..block_size {
                input[block_start + i] = fill_byte;
            }
        } else {
            // 블록 내부를 각각 랜덤값으로
            for i in 0..block_size {
                input[block_start + i] = state.rand_mut().below(256) as u8;
            }
        }

        MutationResult::Mutated
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 6) BlockDuplicateMutator
 *    - (min_block_size..max_block_size) 범위 블록 하나를 골라,
 *      (min_dup..max_dup) 횟수만큼 그 블록을 복제해 붙인다.
 * -------------------------------------------------------------------------*/
#[derive(Debug)]
pub struct BlockDuplicateMutator {
    min_block_size: usize,
    max_block_size: usize,
    min_dup: usize,
    max_dup: usize,
}

impl BlockDuplicateMutator {
    pub fn new(min_block_size: usize, max_block_size: usize, min_dup: usize, max_dup: usize) -> Self {
        Self {
            min_block_size,
            max_block_size,
            min_dup,
            max_dup,
        }
    }
}

impl<S> Mutator<S, Vec<u8>> for BlockDuplicateMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        let size = input.len();
        if size < self.min_block_size {
            return MutationResult::Skipped;
        }
        let max_b = min(self.max_block_size, size);
        if max_b == 0 {
            return MutationResult::Skipped;
        }
        let block_size = self.min_block_size
            + (state.rand_mut().below((max_b - self.min_block_size + 1) as u64) as usize);

        // block_start
        let block_start = state.rand_mut().below((size - block_size + 1) as u64) as usize;

        // 얼마나 복제할지
        let dup_count = self.min_dup
            + (state.rand_mut().below((self.max_dup - self.min_dup + 1) as u64) as usize);

        // 해당 블록을 dup_count 번 삽입
        let block = input[block_start..block_start + block_size].to_vec();
        for _ in 0..dup_count {
            input.splice(block_start + block_size..block_start + block_size, block.clone());
        }

        MutationResult::Mutated
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 7) InterestingValueMutator
 *    - C++ 예시에서는 dictionary 등을 로드해 특정 바이트열을 삽입.
 *    - 아래는 간단히 정해진 '재미있는 값' (예: 0x00, 0xFF, 0x7F 등)을
 *      임의 위치에 덮어쓰는 식으로 구현.
 * -------------------------------------------------------------------------*/
#[derive(Debug)]
pub struct InterestingValueMutator {
    interesting_values: Vec<Vec<u8>>,
}

impl InterestingValueMutator {
    pub fn new_default() -> Self {
        // 대표적인 "흥미로운 값" 몇 가지
        let knowns: &[&[u8]] = &[
            &[0x00],
            &[0xFF],
            &[0x7F],
            &[0x80],
            &[0x01, 0x00], // 16-bit
            &[0xFF, 0xFF],
            &[0x7F, 0xFF],
            &[0x00, 0x00, 0x00, 0x00], // 32-bit
            &[0xFF, 0xFF, 0xFF, 0xFF],
        ];
        let ivs = knowns.iter().map(|x| x.to_vec()).collect();
        Self {
            interesting_values: ivs,
        }
    }

    pub fn with_values(values: Vec<Vec<u8>>) -> Self {
        Self { interesting_values: values }
    }
}

impl<S> Mutator<S, Vec<u8>> for InterestingValueMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        if input.is_empty() || self.interesting_values.is_empty() {
            return MutationResult::Skipped;
        }
        // 임의로 interesting value 선택
        let idx_iv = state.rand_mut().below(self.interesting_values.len() as u64) as usize;
        let val = &self.interesting_values[idx_iv];
        let val_len = val.len();
        if val_len > input.len() {
            return MutationResult::Skipped;
        }
        let pos = state.rand_mut().below((input.len() - val_len + 1) as u64) as usize;
        input[pos..(pos+val_len)].copy_from_slice(val);

        MutationResult::Mutated
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 8) SpliceMutator
 *    - 2개의 입력 중 한쪽에 다른 쪽의 바이트를 섞어 넣는다.
 *    - LibAFL에서는 Crossover류로 분류됨.
 *    - 여기선 무작위로 splice point(s)를 정해 교차한다.
 *
 *    - 실무에선 '두 번째 corpus input'을 어떻게 가져올지 고민 필요.
 *      HavocCrossover 처럼, or WeightedUnion의 mutate_secondary_input, ...
 *    - 간단히 "다른 sample"이라고 해서 인자로 받도록 가정.
 * -------------------------------------------------------------------------*/
#[derive(Debug)]
pub struct SpliceMutator {
    points: u8,
    displacement_p: f32,
    other_input: Vec<u8>,
}

impl SpliceMutator {
    /// `points`: splice 지점 수 (1 or 2)
    /// `displacement_p`: 0.0~1.0 사이, true면 임의 offset으로 교차
    /// `other_input`: 교차에 사용할 다른 샘플(단순히 Vec<u8>)
    pub fn new(points: u8, displacement_p: f32, other_input: Vec<u8>) -> Self {
        Self {
            points,
            displacement_p,
            other_input,
        }
    }
}

impl<S> Mutator<S, Vec<u8>> for SpliceMutator
where
    S: HasRand,
{
    fn mutate(&self, state: &mut S, input: &mut Vec<u8>, _stage_idx: i32) -> MutationResult {
        if input.is_empty() || self.other_input.is_empty() {
            return MutationResult::Skipped;
        }
        let displace = state.rand_mut().below(10000) < (10000.0 * self.displacement_p) as u64;

        // 여기서는 points=1만 간단히 구현
        // points=2 로직은 필요시 추가
        if self.points != 1 {
            // 예시: 그냥 skipped
            return MutationResult::Skipped;
        }

        // 점 한곳에서 splice
        let input_len = input.len();
        let other_len = self.other_input.len();
        if displace {
            // random offset 교차
            // blockstart1, blocksize1 from input
            let start1 = state.rand_mut().below(input_len as u64) as usize;
            let start2 = state.rand_mut().below(other_len as u64) as usize;

            // 임의 길이를 정해본다(여기서는 짧게)
            let max_copy = min(input_len - start1, other_len - start2);
            if max_copy == 0 {
                return MutationResult::Skipped;
            }
            let copy_len = state.rand_mut().below(max_copy as u64) as usize;
            if copy_len == 0 {
                return MutationResult::Skipped;
            }

            // 덮어쓰기
            input[start1..start1+copy_len]
                .copy_from_slice(&self.other_input[start2..start2+copy_len]);
        } else {
            // "동일 offset" splice
            let offset = state.rand_mut().below(min(input_len, other_len) as u64) as usize;
            let copy_len = min(input_len - offset, other_len - offset);
            if copy_len == 0 {
                return MutationResult::Skipped;
            }
            input[offset..offset+copy_len]
                .copy_from_slice(&self.other_input[offset..offset+copy_len]);
        }

        MutationResult::Mutated
    }
    fn post_exec(&self, _state: &mut S, _input: &mut Vec<u8>, _stage_idx: i32, _was_timeout: bool) {}
}

/* ---------------------------------------------------------------------------
 * 9) WeightedUnionMutator 로 "pselect" 처럼 확률적으로 여러 mutator를 결합
 * -------------------------------------------------------------------------*/

use libafl::mutators::scheduled::weights::WeightedUnionMutator;

/// 사용자가 원하는 확률(가중치)에 맞춰 생성
/// C++ 예시에 나타난 확률 비율을 대충 대응시킴:
///  - ByteFlipMutator: 0.8
///  - ArithmeticMutator: 0.2
///  - AppendMutator(1..128): 0.2
///  - BlockInsertMutator(1..128): 0.1
///  - BlockFlipMutator(2..16): 0.1
///  - BlockFlipMutator(16..64): 0.1
///  - BlockFlipMutator(1..64, uniform=true): 0.1
///  - BlockDuplicateMutator(1..128, 1..8): 0.05
///  - BlockDuplicateMutator(1..16, 1..64): 0.05
///  - InterestingValueMutator: 0.1
///  - SpliceMutator(1, 0.5): 0.1
///  - SpliceMutator(2, 0.5): 0.1
/// 
/// LibAFL의 WeightedUnionMutator 는 정수 가중치를 사용합니다.
/// 위 확률을 10배 등 적당히 스케일해서 정수화하겠습니다.
pub fn create_custom_mutation_suite(other_corpus_sample: Vec<u8>) -> WeightedUnionMutator<
    impl HasRand,
    Vec<u8>,
> {
    // 아래 확률 합은 1.0 이상으로 보이지만, WeightedUnionMutator는
    // "합"을 정규화하므로 크게 상관 없습니다.
    // 예: 0.8 => 8, 0.2 => 2, ... 로 단순 스케일
    // 다만, SpliceMutator(2,0.5)등 일부는 위 예시에서 단순히 skip하도록 했지만,
    // 필요시 로직 추가 구현 가능.
    WeightedUnionMutator::new(vec![
        (Box::new(ByteFlipMutator::new()), 8),          // 0.8
        (Box::new(ArithmeticMutator::new()), 2),        // 0.2
        (Box::new(AppendMutator::new(1,128)), 2),       // 0.2
        (Box::new(BlockInsertMutator::new(1,128)), 1),  // 0.1
        (Box::new(BlockFlipMutator::new(2,16,false)), 1),    // 0.1
        (Box::new(BlockFlipMutator::new(16,64,false)), 1),   // 0.1
        (Box::new(BlockFlipMutator::new(1,64,true)), 1),     // 0.1
        (Box::new(BlockDuplicateMutator::new(1,128,1,8)), 1),   // 0.05
        (Box::new(BlockDuplicateMutator::new(1,16,1,64)), 1),   // 0.05
        (Box::new(InterestingValueMutator::new_default()), 1),  // 0.1

        // SpliceMutator(1, 0.5)
        (
            Box::new(SpliceMutator::new(1, 0.5, other_corpus_sample.clone())),
            1
        ),
        // SpliceMutator(2, 0.5) => 현재는 points=2에서 Skipped 처리이므로 
        //                          예시로만 포함. 실제 구현시 추가 로직 필요.
        (
            Box::new(SpliceMutator::new(2, 0.5, other_corpus_sample.clone())),
            1
        ),
    ])
}

// 예시 끝