use ocl::{Buffer, Kernel, MemFlags, Platform, ProQue, SpatialDims};
use std::ops::Range;
use thiserror::Error;

pub use ocl;

#[derive(Debug)]
pub struct Scrypter {
    kernel: Kernel,
    output: Buffer<u8>,
    global_work_size: usize,
    pro_que: ProQue,

    vrf_nonce_buf: Buffer<u64>,
    vrf_nonce: Option<u64>,
    search_for_vrf_nonce: bool,
}

#[derive(Error, Debug)]
pub enum ScryptError {
    #[error("Labels range too big to fit in usize")]
    LabelsRangeTooBig,
    #[error("Invalid buffer size: got {got}, expected {expected}")]
    InvalidBufferSize { got: usize, expected: usize },
    #[error("Fail in OpenCL: {0}")]
    OclError(#[from] ocl::Error),
    #[error("Fail in OpenCL core: {0}")]
    OclCoreError(#[from] ocl::OclCoreError),
}

const LABEL_SIZE: usize = 16;

pub fn get_providers_count() -> usize {
    match ocl::core::get_platform_ids() {
        Ok(ids) => ids.len(),
        Err(_) => 0,
    }
}

impl Scrypter {
    pub fn new(
        provider_id: Option<usize>,
        n: usize,
        commitment: &[u8; 32],
        vrf_difficulty: Option<&[u8; 32]>,
    ) -> Result<Self, ScryptError> {
        let platform_id = if let Some(provider_id) = provider_id {
            ocl::core::get_platform_ids()?[provider_id]
        } else {
            ocl::core::default_platform()?
        };
        let platform = Platform::new(platform_id);

        //TODO remove print
        eprintln!("Using platform: {:?}", platform.name().unwrap());

        let src = include_str!("scrypt-jane.cl");
        let mut pro_que = ProQue::builder().src(src).platform(platform).build()?;

        let max_wg_size = pro_que.device().max_wg_size()?;
        let global_work_size = max_wg_size * 2;

        pro_que.set_dims(SpatialDims::One(global_work_size));

        let commitment: Vec<u32> = commitment
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        let input = Buffer::<u32>::builder()
            .len(8)
            .copy_host_slice(commitment.as_slice())
            .flags(MemFlags::new().read_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let output = Buffer::<u8>::builder()
            .len(global_work_size * LABEL_SIZE)
            .flags(MemFlags::new().write_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let vrf_nonce_buf = Buffer::<u64>::builder()
            .len(1)
            .fill_val(u64::MAX)
            .flags(MemFlags::new().write_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let mut vrf_difficulty_builder = Buffer::<u8>::builder()
            .len(32)
            .flags(MemFlags::new().read_only())
            .queue(pro_que.queue().clone());
        if let Some(vrf_difficulty) = vrf_difficulty {
            vrf_difficulty_builder = vrf_difficulty_builder.copy_host_slice(vrf_difficulty);
        }

        let vrf_difficulty_buf = vrf_difficulty_builder.build()?;

        let lookup_gap = 2;
        let pad_size = global_work_size * 4 * 8 * (n / lookup_gap);

        let padcache = Buffer::<u32>::builder()
            .len(pad_size)
            .flags(MemFlags::new().host_no_access())
            .queue(pro_que.queue().clone())
            .build()?;

        let kernel = pro_que
            .kernel_builder("scrypt")
            .arg(n as u32)
            .arg(0u64)
            .arg(&input)
            .arg(&output)
            .arg(&padcache)
            .arg(if vrf_difficulty.is_some() { 1u8 } else { 0 })
            .arg(&vrf_difficulty_buf)
            .arg(&vrf_nonce_buf)
            .global_work_size(SpatialDims::One(global_work_size))
            .local_work_size(128)
            .build()?;

        Ok(Self {
            pro_que,
            kernel,
            output,
            global_work_size,
            vrf_nonce_buf,
            vrf_nonce: None,
            search_for_vrf_nonce: vrf_difficulty.is_some(),
        })
    }

    pub fn device(&self) -> ocl::Device {
        self.pro_que.device()
    }

    pub fn vrf_nonce(&self) -> Option<u64> {
        self.vrf_nonce
    }

    pub fn buffer_len(labels: &Range<u64>) -> Result<usize, ScryptError> {
        match usize::try_from(labels.end - labels.start) {
            Ok(len) => Ok(len * LABEL_SIZE),
            Err(_) => Err(ScryptError::LabelsRangeTooBig),
        }
    }

    pub fn scrypt(
        &mut self,
        labels: Range<u64>,
        out: &mut [u8],
    ) -> Result<Option<u64>, ScryptError> {
        let expected_len = Self::buffer_len(&labels)?;
        if out.len() != expected_len {
            return Err(ScryptError::InvalidBufferSize {
                got: out.len(),
                expected: expected_len,
            });
        }

        for (id, chunk) in out
            .chunks_mut(self.global_work_size * LABEL_SIZE)
            .enumerate()
        {
            let start_index = labels.start + self.global_work_size as u64 * id as u64;
            self.kernel.set_arg(1, start_index)?;

            if self.vrf_nonce.is_none() && self.search_for_vrf_nonce {
                // enable vrf search
                self.kernel.set_arg(5, 1u8)?;
            }

            unsafe {
                self.kernel.enq()?;
            }

            self.output.read(chunk).enq()?;

            if self.vrf_nonce.is_none() && self.search_for_vrf_nonce {
                // Read vrf nonce
                let mut nonce = [0u64; 1];
                self.vrf_nonce_buf.read(nonce.as_mut_slice()).enq()?;
                if nonce[0] != u64::MAX {
                    self.vrf_nonce = Some(nonce[0]);
                }
            }
        }
        Ok(self.vrf_nonce)
    }
}

#[cfg(test)]
mod tests {
    use post::ScryptParams;

    use super::*;

    #[test]
    fn scrypting_from_0() {
        let indices = 0..70;

        let mut scrypter = Scrypter::new(None, 8192, &[0u8; 32], None).unwrap();
        let mut labels = vec![0u8; Scrypter::buffer_len(&indices).unwrap()];
        let _ = scrypter.scrypt(indices.clone(), &mut labels).unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        post::initialize::initialize_to(
            &mut expected,
            &[0u8; 32],
            indices,
            ScryptParams::new(12, 0, 0),
        )
        .unwrap();

        assert_eq!(expected, labels);
    }

    #[test]
    fn scrypting_over_4gb() {
        let indices = u32::MAX as u64 - 32..u32::MAX as u64 + 32;

        let mut scrypter = Scrypter::new(None, 8192, &[0u8; 32], None).unwrap();
        let mut labels = vec![0u8; Scrypter::buffer_len(&indices).unwrap()];
        let _ = scrypter.scrypt(indices.clone(), &mut labels).unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        post::initialize::initialize_to(
            &mut expected,
            &[0u8; 32],
            indices,
            ScryptParams::new(12, 0, 0),
        )
        .unwrap();

        assert_eq!(expected, labels);
    }

    #[test]
    fn scrypting_with_commitment() {
        let indices = 0..70;
        let commitment = b"this is some commitment for init";

        let mut scrypter = Scrypter::new(None, 8192, commitment, None).unwrap();
        let mut labels = vec![0u8; Scrypter::buffer_len(&indices).unwrap()];
        let _ = scrypter.scrypt(indices.clone(), &mut labels).unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        post::initialize::initialize_to(
            &mut expected,
            commitment,
            indices,
            ScryptParams::new(12, 0, 0),
        )
        .unwrap();

        assert_eq!(expected, labels);
    }

    #[test]
    fn searching_for_vrf_nonce() {
        let indices = 0..1024 * 5;
        let commitment = b"this is some commitment for init";
        let mut difficulty = [0xFFu8; 32];
        difficulty[0] = 0;
        difficulty[1] = 0x1F;

        let mut scrypter = Scrypter::new(None, 8192, commitment, Some(&difficulty)).unwrap();
        let mut labels = vec![0u8; Scrypter::buffer_len(&indices).unwrap()];
        let nonce = scrypter.scrypt(indices, &mut labels).unwrap();

        assert!(nonce.is_some());

        let mut label = Vec::<u8>::with_capacity(LABEL_SIZE);
        post::initialize::initialize_to(
            &mut label,
            commitment,
            nonce.unwrap()..nonce.unwrap() + 1,
            ScryptParams::new(12, 0, 0),
        )
        .unwrap();

        assert!(label.as_slice() < &difficulty);
    }
}
