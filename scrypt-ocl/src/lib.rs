extern crate ocl;

use std::{error::Error, ops::Range};

use ocl::{Buffer, Kernel, MemFlags, ProQue, SpatialDims};

#[derive(Debug)]
pub struct Scrypter {
    kernel: Kernel,
    input: Buffer<u32>,
    output: Buffer<u8>,
    global_work_size: usize,
    pro_que: ProQue,
}

const LABEL_SIZE: usize = 16;

impl Scrypter {
    pub fn new(n: usize) -> ocl::Result<Self> {
        let src = include_str!("scrypt-jane.cl");
        let mut pro_que = ProQue::builder().src(src).build()?;

        let max_wg_size = pro_que.device().max_wg_size()?;
        let global_work_size = max_wg_size * 2;

        pro_que.set_dims(SpatialDims::One(global_work_size));

        let input = Buffer::<u32>::builder()
            .len(8)
            .flags(MemFlags::new().read_only())
            .queue(pro_que.queue().clone())
            .build()?;

        let output = Buffer::<u8>::builder()
            .len(global_work_size * LABEL_SIZE)
            .flags(MemFlags::new().write_only())
            .queue(pro_que.queue().clone())
            .build()?;

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
            .global_work_size(SpatialDims::One(global_work_size))
            .local_work_size(128)
            .build()?;

        Ok(Self {
            pro_que,
            kernel,
            input,
            output,
            global_work_size,
        })
    }

    pub fn device(&self) -> ocl::Device {
        self.pro_que.device()
    }

    pub fn scrypt(
        &mut self,
        commitment: &[u8; 32],
        labels: Range<u64>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let num_labels = usize::try_from(labels.end - labels.start)?;
        let mut vec = vec![0u8; num_labels * LABEL_SIZE];
        for (id, chunk) in vec
            .chunks_mut(self.global_work_size * LABEL_SIZE)
            .enumerate()
        {
            let start_index = labels.start + self.global_work_size as u64 * id as u64;
            self.input.write(bytemuck::cast_slice(commitment)).enq()?;
            self.kernel.set_arg(1, start_index)?;
            unsafe {
                self.kernel.enq()?;
            }

            self.output.read(chunk).enq()?;
        }
        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use post::ScryptParams;

    use super::*;

    #[test]
    fn scrypting_from_0() {
        let indices = 0..70;

        let mut scrypter = Scrypter::new(8192).unwrap();
        let labels = scrypter.scrypt(&[0u8; 32], indices.clone()).unwrap();

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

        let mut scrypter = Scrypter::new(8192).unwrap();
        let labels = scrypter.scrypt(&[0u8; 32], indices.clone()).unwrap();

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

        let mut scrypter = Scrypter::new(8192).unwrap();
        let labels = scrypter.scrypt(commitment, indices.clone()).unwrap();

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
}
