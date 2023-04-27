use ocl::{
    builders::ProgramBuilder,
    enums::{DeviceInfo, DeviceInfoResult, KernelWorkGroupInfo, KernelWorkGroupInfoResult},
    Buffer, Device, Kernel, MemFlags, Platform, ProQue, SpatialDims,
};
use std::{cmp::min, ops::Range};
use thiserror::Error;

pub use ocl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfNonce {
    pub index: u64,
    label: [u8; 32],
}

#[derive(Debug)]
pub struct Scrypter {
    kernel: Kernel,
    output: Buffer<u8>,
    global_work_size: usize,
    pro_que: ProQue,

    vrf_nonce: Option<VrfNonce>,
    vrf_difficulty: Option<[u8; 32]>,
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
const ENTIRE_LABEL_SIZE: usize = 32;

pub fn get_providers_count() -> usize {
    match ocl::core::get_platform_ids() {
        Ok(ids) => ids.len(),
        Err(_) => 0,
    }
}

macro_rules! cast {
    ($target: expr, $pat: path) => {{
        if let $pat(a) = $target {
            // #1
            a
        } else {
            panic!("mismatch variant when cast to {}", stringify!($pat)); // #2
        }
    }};
}

impl Scrypter {
    pub fn new(
        provider_id: Option<usize>,
        n: usize,
        commitment: &[u8; 32],
        vrf_difficulty: Option<[u8; 32]>,
    ) -> Result<Self, ScryptError> {
        let platform_id = if let Some(provider_id) = provider_id {
            ocl::core::get_platform_ids()?[provider_id]
        } else {
            ocl::core::default_platform()?
        };
        let platform = Platform::new(platform_id);
        let device = Device::first(platform)?;
        // TODO remove print
        println!(
            "Using platform/device: {}/{}",
            platform.name().unwrap(),
            device.name().unwrap()
        );

        // Calculate kernel memory requirements
        const LOOKUP_GAP: usize = 2;
        const SCRYPT_MEM: usize = 128;
        const INPUT_SIZE: usize = 32;

        let kernel_lookup_mem_size = n / LOOKUP_GAP * SCRYPT_MEM;
        let kernel_output_mem_size = ENTIRE_LABEL_SIZE;
        let kernel_memory = kernel_lookup_mem_size + kernel_output_mem_size;

        // Query device parameters
        let device_memory = cast!(
            device.info(DeviceInfo::GlobalMemSize)?,
            DeviceInfoResult::GlobalMemSize
        );
        let max_mem_alloc_size = cast!(
            device.info(DeviceInfo::MaxMemAllocSize)?,
            DeviceInfoResult::MaxMemAllocSize
        );
        let max_compute_units = cast!(
            device.info(DeviceInfo::MaxComputeUnits)?,
            DeviceInfoResult::MaxComputeUnits
        );
        let max_wg_size = device.max_wg_size()?;
        println!(
            "device memory: {} MB, max_mem_alloc_size: {} MB, max_compute_units: {max_compute_units}, max_wg_size: {max_wg_size}",
            device_memory / 1024 / 1024,
            max_mem_alloc_size / 1024 / 1024,
        );

        let src = include_str!("scrypt-jane.cl");
        let program_builder = ProgramBuilder::new()
            .source(src)
            .cmplr_def("LOOKUP_GAP", LOOKUP_GAP as i32)
            .clone();

        let pro_que = ProQue::builder()
            .platform(platform)
            .device(device)
            .prog_bldr(program_builder)
            .dims(1)
            .build()?;

        let mut kernel = pro_que
            .kernel_builder("scrypt")
            .arg(n as u32)
            .arg(0u64)
            .arg(pro_que.buffer_builder::<u32>().build()?)
            .arg(pro_que.buffer_builder::<u8>().build()?)
            .arg(pro_que.buffer_builder::<u32>().build()?)
            .build()?;

        let preferred_wg_size_multiple = cast!(
            kernel.wg_info(device, KernelWorkGroupInfo::PreferredWorkGroupSizeMultiple)?,
            KernelWorkGroupInfoResult::PreferredWorkGroupSizeMultiple
        );
        let kernel_wg_size = kernel.wg_info(device, KernelWorkGroupInfo::WorkGroupSize)?;

        println!("preferred_wg_size_multiple: {preferred_wg_size_multiple}, kernel_wg_size: {kernel_wg_size}");

        let max_global_work_size_based_on_total_mem =
            ((device_memory - INPUT_SIZE as u64) / kernel_memory as u64) as usize;
        let max_global_work_size_based_on_max_mem_alloc_size =
            (max_mem_alloc_size / kernel_lookup_mem_size as u64) as usize;
        let max_global_work_size = min(
            max_global_work_size_based_on_max_mem_alloc_size,
            max_global_work_size_based_on_total_mem,
        );
        let local_work_size = preferred_wg_size_multiple;
        // Round down to nearest multiple of local_work_size
        let global_work_size = (max_global_work_size / local_work_size) * local_work_size;
        eprintln!(
            "Using: global_work_size: {global_work_size}, local_work_size: {local_work_size}"
        );

        let commitment: Vec<u32> = commitment
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        println!("Allocating buffer for input: {INPUT_SIZE} bytes");
        let input = Buffer::<u32>::builder()
            .len(INPUT_SIZE / 4)
            .copy_host_slice(commitment.as_slice())
            .flags(MemFlags::new().read_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let output_size = global_work_size * ENTIRE_LABEL_SIZE;
        println!("Allocating buffer for output: {output_size} bytes");
        let output = Buffer::<u8>::builder()
            .len(output_size)
            .flags(MemFlags::new().write_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let lookup_size = global_work_size * kernel_lookup_mem_size;
        println!("Allocating buffer for lookup: {lookup_size} bytes");
        let lookup_memory = Buffer::<u32>::builder()
            .len(lookup_size / 4)
            .flags(MemFlags::new().host_no_access())
            .queue(pro_que.queue().clone())
            .build()?;

        kernel.set_arg(2, &input)?;
        kernel.set_arg(3, &output)?;
        kernel.set_arg(4, &lookup_memory)?;
        kernel.set_default_global_work_size(SpatialDims::One(global_work_size));
        kernel.set_default_local_work_size(SpatialDims::One(local_work_size));

        Ok(Self {
            pro_que,
            kernel,
            output,
            global_work_size,
            vrf_difficulty,
            vrf_nonce: None,
        })
    }

    pub fn device(&self) -> ocl::Device {
        self.pro_que.device()
    }

    pub fn vrf_nonce(&self) -> Option<VrfNonce> {
        self.vrf_nonce
    }

    pub fn buffer_len(labels: &Range<u64>) -> Result<usize, ScryptError> {
        match usize::try_from(labels.end - labels.start) {
            Ok(len) => Ok(len * LABEL_SIZE),
            Err(_) => Err(ScryptError::LabelsRangeTooBig),
        }
    }

    fn scan_for_vrf_nonce(labels: &[u8], mut difficulty: [u8; 32]) -> Option<VrfNonce> {
        let mut nonce = None;
        for (id, label) in labels.chunks(ENTIRE_LABEL_SIZE).enumerate() {
            if label < &difficulty {
                nonce = Some(VrfNonce {
                    index: id as u64,
                    label: label.try_into().unwrap(),
                });
                difficulty = label.try_into().unwrap();
            }
        }
        nonce
    }

    pub fn scrypt(
        &mut self,
        labels: Range<u64>,
        out: &mut [u8],
    ) -> Result<Option<VrfNonce>, ScryptError> {
        let expected_len = Self::buffer_len(&labels)?;
        if out.len() != expected_len {
            return Err(ScryptError::InvalidBufferSize {
                got: out.len(),
                expected: expected_len,
            });
        }

        let mut labels_buffer = vec![0u8; self.global_work_size * ENTIRE_LABEL_SIZE];

        let mut index = labels.start;
        for chunk in &mut out.chunks_mut(self.global_work_size * LABEL_SIZE) {
            self.kernel.set_arg(1, index)?;
            let labels_to_init = chunk.len() / LABEL_SIZE;
            index += labels_to_init as u64;

            if labels_to_init < self.global_work_size {
                self.kernel
                    .set_default_global_work_size(SpatialDims::One(labels_to_init));
            }

            unsafe {
                self.kernel.enq()?;
            }

            let labels_buffer =
                &mut labels_buffer.as_mut_slice()[..labels_to_init * ENTIRE_LABEL_SIZE];
            self.output.read(labels_buffer.as_mut()).enq()?;

            // Look for VRF nonce if enabled
            // TODO: run in background / in parallel to GPU
            if let Some(difficulty) = &self.vrf_difficulty {
                let new_best_nonce = match self.vrf_nonce {
                    Some(current_smallest) => {
                        Self::scan_for_vrf_nonce(labels_buffer, current_smallest.label)
                    }
                    None => Self::scan_for_vrf_nonce(labels_buffer, *difficulty),
                };
                if let Some(nonce) = new_best_nonce {
                    self.vrf_nonce = Some(VrfNonce {
                        index: nonce.index + index,
                        label: nonce.label,
                    });
                    //TODO: remove print
                    eprintln!("Found new smallest nonce: {:?}", self.vrf_nonce);
                }
            }

            // Copy the first 16 bytes of each label
            // TODO: run in background / in parallel to GPU
            for (full_label, out_label) in labels_buffer
                .chunks_exact(ENTIRE_LABEL_SIZE)
                .zip(chunk.chunks_exact_mut(LABEL_SIZE))
            {
                out_label.copy_from_slice(&full_label[..LABEL_SIZE]);
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
    fn scanning_for_vrf_nonce() {
        let labels = [[0xFF; 32], [0xEE; 32], [0xDD; 32], [0xEE; 32]];
        let labels_bytes: Vec<u8> = labels.iter().copied().flatten().collect();
        let nonce = Scrypter::scan_for_vrf_nonce(&labels_bytes, [0xFFu8; 32]);
        assert_eq!(
            nonce,
            Some(VrfNonce {
                index: 2,
                label: [0xDD; 32]
            })
        );
    }

    #[test]
    fn scrypting_from_0() {
        let indices = 0..4000;

        let mut scrypter = Scrypter::new(None, 8192, &[0u8; 32], None).unwrap();
        let mut labels = vec![0xDEu8; Scrypter::buffer_len(&indices).unwrap()];
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
        let indices = u32::MAX as u64 - 1000..u32::MAX as u64 + 1000;

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
        let indices = 0..1000;
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
        let indices = 0..5000;
        let commitment = b"this is some commitment for init";
        let mut difficulty = [0xFFu8; 32];
        difficulty[0] = 0;
        difficulty[1] = 0x1F;

        let mut scrypter = Scrypter::new(None, 8192, commitment, Some(difficulty)).unwrap();
        let mut labels = vec![0u8; Scrypter::buffer_len(&indices).unwrap()];
        let nonce = scrypter.scrypt(indices, &mut labels).unwrap();
        let nonce = nonce.expect("vrf nonce not found");

        let mut label = Vec::<u8>::with_capacity(LABEL_SIZE);
        post::initialize::initialize_to(
            &mut label,
            commitment,
            nonce.index..nonce.index + 1,
            ScryptParams::new(12, 0, 0),
        )
        .unwrap();

        assert_eq!(&nonce.label[..16], label.as_slice());
        assert!(nonce.label.as_slice() < &difficulty);
        assert!(label.as_slice() < &difficulty);
    }
}
