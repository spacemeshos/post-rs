use ocl::{
    builders::ProgramBuilder,
    enums::{DeviceInfo, DeviceInfoResult, KernelWorkGroupInfo, KernelWorkGroupInfoResult},
    Buffer, Device, DeviceType, Kernel, MemFlags, Platform, ProQue, SpatialDims,
};
use post::initialize::{Initialize, VrfNonce, ENTIRE_LABEL_SIZE, LABEL_SIZE};
use std::{cmp::min, fmt::Display, io::Write, ops::Range};
use thiserror::Error;

pub use ocl;

#[derive(Debug)]
struct Scrypter {
    kernel: Kernel,
    input: Buffer<u32>,
    output: Buffer<u8>,
    global_work_size: usize,
    preferred_wg_size_mult: usize,
    labels_buffer: Vec<u8>,
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
    #[error("Invalid provider id: {0:?}")]
    InvalidProviderId(ProviderId),
    #[error("No providers available")]
    NoProvidersAvailable,
    #[error("Failed to write labels: {0}")]
    WriteError(#[from] std::io::Error),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderId(pub u32);

pub struct Provider {
    pub platform: Platform,
    pub device: Device,
    pub class: DeviceType,
}

impl Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {}/{}",
            self.class,
            self.platform.name().unwrap_or("unknown".to_owned()),
            self.device.name().unwrap_or("unknown".to_owned())
        )
    }
}

pub fn get_providers_count(device_types: Option<DeviceType>) -> usize {
    get_providers(device_types).map_or(0, |p| p.len())
}

pub fn get_providers(device_types: Option<DeviceType>) -> Result<Vec<Provider>, ScryptError> {
    let list_core = ocl::core::get_platform_ids()?;
    let platforms = Platform::list_from_core(list_core);

    let mut providers = Vec::new();
    for platform in platforms {
        let devices = Device::list(platform, device_types)?;
        for device in devices {
            providers.push(Provider {
                platform,
                device,
                class: cast!(device.info(DeviceInfo::Type)?, DeviceInfoResult::Type),
            });
        }
    }

    Ok(providers)
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

impl Scrypter {
    pub fn new(platform: Platform, device: Device, n: usize) -> Result<Self, ScryptError> {
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
        log::debug!(
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

        let preferred_wg_size_mult = cast!(
            kernel.wg_info(device, KernelWorkGroupInfo::PreferredWorkGroupSizeMultiple)?,
            KernelWorkGroupInfoResult::PreferredWorkGroupSizeMultiple
        );
        let kernel_wg_size = kernel.wg_info(device, KernelWorkGroupInfo::WorkGroupSize)?;

        log::debug!("preferred_wg_size_multiple: {preferred_wg_size_mult}, kernel_wg_size: {kernel_wg_size}");

        let max_global_work_size_based_on_total_mem =
            ((device_memory - INPUT_SIZE as u64) / kernel_memory as u64) as usize;
        let max_global_work_size_based_on_max_mem_alloc_size =
            (max_mem_alloc_size / kernel_lookup_mem_size as u64) as usize;
        let max_global_work_size = min(
            max_global_work_size_based_on_max_mem_alloc_size,
            max_global_work_size_based_on_total_mem,
        );
        let local_work_size = preferred_wg_size_mult;
        // Round down to nearest multiple of local_work_size
        let global_work_size = (max_global_work_size / local_work_size) * local_work_size;
        log::debug!(
            "Using: global_work_size: {global_work_size}, local_work_size: {local_work_size}"
        );

        log::trace!("Allocating buffer for input: {INPUT_SIZE} bytes");
        let input = Buffer::<u32>::builder()
            .len(INPUT_SIZE / 4)
            .flags(MemFlags::new().read_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let output_size = global_work_size * ENTIRE_LABEL_SIZE;
        log::trace!("Allocating buffer for output: {output_size} bytes");
        let output = Buffer::<u8>::builder()
            .len(output_size)
            .flags(MemFlags::new().write_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let lookup_size = global_work_size * kernel_lookup_mem_size;
        log::trace!("Allocating buffer for lookup: {lookup_size} bytes");
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
            kernel,
            input,
            output,
            global_work_size,
            preferred_wg_size_mult,
            labels_buffer: vec![0u8; global_work_size * ENTIRE_LABEL_SIZE],
        })
    }

    pub fn scrypt<W: std::io::Write + ?Sized>(
        &mut self,
        writer: &mut W,
        labels: Range<u64>,
        commitment: &[u8; 32],
        mut vrf_difficulty: Option<[u8; 32]>,
    ) -> Result<Option<VrfNonce>, ScryptError> {
        let commitment: Vec<u32> = commitment
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        self.input.write(&commitment).enq()?;

        let mut best_nonce = None;
        let labels_end = labels.end;

        for index in labels.step_by(self.global_work_size) {
            self.kernel.set_arg(1, index)?;

            let index_end = min(index + self.global_work_size as u64, labels_end);
            let labels_to_init = (index_end - index) as usize;

            let gws = if labels_to_init < self.global_work_size {
                // Round up labels_to_init to be a multiple of preferred_wg_size_mult
                (labels_to_init + self.preferred_wg_size_mult - 1) / self.preferred_wg_size_mult
                    * self.preferred_wg_size_mult
            } else {
                self.global_work_size
            };
            log::trace!(
                "initializing {index} -> {index_end} ({labels_to_init} labels, GWS: {gws})"
            );
            self.kernel
                .set_default_global_work_size(SpatialDims::One(gws));

            unsafe {
                self.kernel.enq()?;
            }

            let labels_buffer =
                &mut self.labels_buffer.as_mut_slice()[..labels_to_init * ENTIRE_LABEL_SIZE];
            self.output.read(labels_buffer.as_mut()).enq()?;

            // Look for VRF nonce if enabled
            // TODO: run in background / in parallel to GPU
            if let Some(difficulty) = vrf_difficulty {
                if let Some(nonce) = scan_for_vrf_nonce(labels_buffer, difficulty) {
                    best_nonce = Some(VrfNonce {
                        index: nonce.index + index,
                        label: nonce.label,
                    });
                    vrf_difficulty = Some(nonce.label);
                    log::trace!("Found new smallest nonce: {best_nonce:?}");
                }
            }

            // Move labels in labels_buffer, taking only 16B of each label in-place, creating a continuous buffer of 16B labels.
            // TODO: run in background / in parallel to GPU
            let mut dst = 0;
            for label_id in 0..labels_to_init {
                let src = label_id * ENTIRE_LABEL_SIZE;
                labels_buffer.copy_within(src..src + LABEL_SIZE, dst);
                dst += LABEL_SIZE;
            }
            writer.write_all(&labels_buffer[..dst])?;
        }
        Ok(best_nonce)
    }
}

pub struct OpenClInitializer {
    scrypter: Scrypter,
}

impl OpenClInitializer {
    pub fn new(
        provider_id: Option<ProviderId>,
        n: usize,
        device_types: Option<DeviceType>,
    ) -> Result<Self, ScryptError> {
        let providers = get_providers(device_types)?;
        let provider = if let Some(id) = provider_id {
            providers
                .get(id.0 as usize)
                .ok_or(ScryptError::InvalidProviderId(id))?
        } else {
            providers.first().ok_or(ScryptError::NoProvidersAvailable)?
        };
        let platform = provider.platform;
        let device = provider.device;
        log::trace!("Using provider: {provider}");

        let scrypter = Scrypter::new(platform, device, n)?;

        Ok(Self { scrypter })
    }
}

impl Initialize for OpenClInitializer {
    fn initialize_to(
        &mut self,
        writer: &mut dyn Write,
        commitment: &[u8; 32],
        labels: Range<u64>,
        vrf_difficulty: Option<[u8; 32]>,
    ) -> Result<Option<VrfNonce>, Box<dyn std::error::Error>> {
        self.scrypter
            .scrypt(writer, labels, commitment, vrf_difficulty)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use post::{
        initialize::{CpuInitializer, Initialize},
        ScryptParams,
    };
    use rstest::rstest;

    use super::*;

    #[test]
    fn scanning_for_vrf_nonce() {
        let labels = [[0xFF; 32], [0xEE; 32], [0xDD; 32], [0xEE; 32]];
        let labels_bytes: Vec<u8> = labels.iter().copied().flatten().collect();
        let nonce = scan_for_vrf_nonce(&labels_bytes, [0xFFu8; 32]);
        assert_eq!(
            nonce,
            Some(VrfNonce {
                index: 2,
                label: [0xDD; 32]
            })
        );
    }

    #[test]
    fn scrypting_1_label() {
        let mut scrypter = OpenClInitializer::new(None, 8192, None).unwrap();
        let mut labels = Vec::new();
        scrypter
            .initialize_to(&mut labels, &[0u8; 32], 0..1, None)
            .unwrap();

        let mut expected = Vec::with_capacity(1);
        CpuInitializer::new(ScryptParams::new(12, 0, 0))
            .initialize_to(&mut expected, &[0u8; 32], 0..1, None)
            .unwrap();

        assert_eq!(expected, labels);
    }

    #[rstest]
    #[case(512)]
    #[case(1024)]
    #[case(2048)]
    #[case(4096)]
    #[case(8192)]
    fn scrypting_from_0(#[case] n: usize) {
        let indices = 0..4000;

        let mut scrypter = OpenClInitializer::new(None, n, None).unwrap();
        let mut labels = Vec::new();
        scrypter
            .initialize_to(&mut labels, &[0u8; 32], indices.clone(), None)
            .unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        CpuInitializer::new(ScryptParams::new(n.ilog2() as u8 - 1, 0, 0))
            .initialize_to(&mut expected, &[0u8; 32], indices, None)
            .unwrap();

        assert_eq!(expected, labels);
    }

    #[rstest]
    #[case(512)]
    #[case(1024)]
    #[case(2048)]
    #[case(4096)]
    #[case(8192)]
    fn scrypting_over_4gb(#[case] n: usize) {
        let indices = u32::MAX as u64 - 1000..u32::MAX as u64 + 1000;

        let mut scrypter = OpenClInitializer::new(None, n, None).unwrap();
        let mut labels = Vec::new();
        scrypter
            .initialize_to(&mut labels, &[0u8; 32], indices.clone(), None)
            .unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        CpuInitializer::new(ScryptParams::new(n.ilog2() as u8 - 1, 0, 0))
            .initialize_to(&mut expected, &[0u8; 32], indices, None)
            .unwrap();

        assert_eq!(expected, labels);
    }

    #[test]
    fn scrypting_with_commitment() {
        let indices = 0..1000;
        let commitment = b"this is some commitment for init";

        let mut scrypter = OpenClInitializer::new(None, 8192, None).unwrap();
        let mut labels = Vec::new();
        scrypter
            .initialize_to(&mut labels, commitment, indices.clone(), None)
            .unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        CpuInitializer::new(ScryptParams::new(12, 0, 0))
            .initialize_to(&mut expected, commitment, indices, None)
            .unwrap();

        assert_eq!(expected, labels);
    }

    #[rstest]
    #[case(512)]
    #[case(1024)]
    #[case(2048)]
    #[case(4096)]
    #[case(8192)]
    fn searching_for_vrf_nonce(#[case] n: usize) {
        let indices = 0..6000;
        let commitment = b"this is some commitment for init";
        let mut difficulty = [0xFFu8; 32];
        difficulty[0] = 0;
        difficulty[1] = 0x2F;

        let mut scrypter = OpenClInitializer::new(None, n, None).unwrap();
        let mut labels = Vec::new();
        let opencl_nonce = scrypter
            .initialize_to(&mut labels, commitment, indices.clone(), Some(difficulty))
            .unwrap();
        let nonce = opencl_nonce.expect("vrf nonce not found");

        let mut label = Vec::<u8>::with_capacity(LABEL_SIZE);
        let mut cpu_initializer = CpuInitializer::new(ScryptParams::new(n.ilog2() as u8 - 1, 0, 0));
        cpu_initializer
            .initialize_to(&mut label, commitment, nonce.index..nonce.index + 1, None)
            .unwrap();

        assert_eq!(&nonce.label[..16], label.as_slice());
        assert!(nonce.label.as_slice() < &difficulty);
        assert!(label.as_slice() < &difficulty);

        let mut sink = std::io::sink();
        let cpu_nonce = cpu_initializer
            .initialize_to(&mut sink, commitment, indices, Some(difficulty))
            .unwrap();

        assert_eq!(cpu_nonce, opencl_nonce);
    }

    #[test]
    fn initialize_in_batches() {
        const N: usize = 512;

        let mut initializer = OpenClInitializer::new(None, N, None).unwrap();
        let gws = initializer.scrypter.global_work_size as u64;

        let mut labels = Vec::<u8>::new();

        // Initialize 2 GWS in two batches, first smaller then the second
        let indices = 0..2 * gws;
        let smaller_batch = gws / 3;

        initializer
            .initialize_to(&mut labels, &[0u8; 32], indices.start..smaller_batch, None)
            .unwrap();
        initializer
            .initialize_to(&mut labels, &[0u8; 32], smaller_batch..indices.end, None)
            .unwrap();

        let mut expected =
            Vec::<u8>::with_capacity(usize::try_from(indices.end - indices.start).unwrap());

        CpuInitializer::new(ScryptParams::new(N.ilog2() as u8 - 1, 0, 0))
            .initialize_to(&mut expected, &[0u8; 32], indices, None)
            .unwrap();

        let mut post_data = std::fs::File::create("labels.bin").unwrap();
        post_data.write_all(&labels).unwrap();

        let mut expected_data = std::fs::File::create("expected.bin").unwrap();
        expected_data.write_all(&expected).unwrap();

        assert_eq!(expected.len(), labels.len());
        assert_eq!(expected, labels);
    }
}
