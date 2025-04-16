use crate::{Errors, get_chunk_sizes};
use blake3;
use ocl::{Buffer, ProQue};

pub fn dynamic_shift_gpu(data: &[u8], nonce: &[u8], password: &[u8]) -> Result<Vec<u8>, Errors> {
    let src = include_str!("atom_gpu.cl");

    if ocl::Platform::list().is_empty() {
        return Err(Errors::KernelError(
            "Cannot find OpenCL platform".to_string(),
        ));
    }

    // Key derivation using Blake3: nonce + password
    let key_hash = blake3::hash(&[nonce, password].concat());
    let key = key_hash.as_bytes();

    // Compute chunk sizes (using your get_chunk_sizes function)
    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key.clone());
    // Convert chunk sizes to u32 for OpenCL and calculate offsets
    let chunk_sizes_u32: Vec<u32> = chunk_sizes.iter().copied().map(|s| s as u32).collect();
    let mut chunk_offsets = Vec::with_capacity(chunk_sizes_u32.len());
    let mut sum = 0;
    for &size in &chunk_sizes_u32 {
        chunk_offsets.push(sum);
        sum += size;
    }

    // Set work size to the number of chunks
    let work_size = chunk_sizes_u32.len();

    // Build ProQue with dims equal to number of chunks
    let pro_que = ProQue::builder()
        .src(src)
        .dims(work_size)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    // Create buffers
    let data_buf = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(data.len())
        .copy_host_slice(data)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let nonce_buf = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(nonce.len())
        .copy_host_slice(nonce)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let key_buf = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(key.len())
        .copy_host_slice(key)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let size_buf = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(chunk_sizes_u32.len())
        .copy_host_slice(&chunk_sizes_u32)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let offset_buf = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(chunk_offsets.len())
        .copy_host_slice(&chunk_offsets)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    // Build and enqueue kernel call (for dynamic_chunk_shift)
    let kernel = pro_que
        .kernel_builder("dynamic_chunk_shift")
        .arg(&data_buf)
        .arg(&nonce_buf)
        .arg(&key_buf)
        .arg(&offset_buf)
        .arg(&size_buf)
        .arg(nonce.len() as u32)
        .arg(key.len() as u32)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    unsafe {
        kernel
            .enq()
            .map_err(|e| Errors::KernelError(e.to_string()))?;
    }

    // Read the processed data back
    let mut out = vec![0u8; data.len()];
    data_buf
        .read(&mut out)
        .enq()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    Ok(out.iter().rev().cloned().collect::<Vec<u8>>())
}

pub fn dynamic_unshift_gpu(data: &[u8], nonce: &[u8], password: &[u8]) -> Result<Vec<u8>, Errors> {
    let src = include_str!("atom_gpu.cl");
    let data = data.iter().rev().cloned().collect::<Vec<u8>>();

    if ocl::Platform::list().is_empty() {
        return Err(Errors::KernelError(
            "Cannot find OpenCL platform".to_string(),
        ));
    }

    let key_hash = blake3::hash(&[nonce, password].concat());
    let key = key_hash.as_bytes();

    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key.clone());
    let chunk_sizes_u32: Vec<u32> = chunk_sizes.iter().copied().map(|s| s as u32).collect();
    let mut chunk_offsets = Vec::with_capacity(chunk_sizes_u32.len());
    let mut sum = 0;
    for &size in &chunk_sizes_u32 {
        chunk_offsets.push(sum);
        sum += size;
    }
    let work_size = chunk_sizes_u32.len();

    let pro_que = ProQue::builder()
        .src(src)
        .dims(work_size)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    let data_buf = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(data.len())
        .copy_host_slice(&data)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let nonce_buf = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(nonce.len())
        .copy_host_slice(nonce)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let key_buf = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(key.len())
        .copy_host_slice(key)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let size_buf = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(chunk_sizes_u32.len())
        .copy_host_slice(&chunk_sizes_u32)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;
    let offset_buf = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(chunk_offsets.len())
        .copy_host_slice(&chunk_offsets)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    let kernel = pro_que
        .kernel_builder("dynamic_chunk_unshift")
        .arg(&data_buf)
        .arg(&nonce_buf)
        .arg(&key_buf)
        .arg(&offset_buf)
        .arg(&size_buf)
        .arg(nonce.len() as u32)
        .arg(key.len() as u32)
        .build()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    unsafe {
        kernel
            .enq()
            .map_err(|e| Errors::KernelError(e.to_string()))?;
    }

    let mut out = vec![0u8; data.len()];
    data_buf
        .read(&mut out)
        .enq()
        .map_err(|e| Errors::KernelError(e.to_string()))?;

    Ok(out)
}
