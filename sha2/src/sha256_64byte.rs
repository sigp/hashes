use digest::{generic_array::GenericArray, typenum::U64};

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod x86;
        use x86::compress_64byte;
    }
}

/// Raw SHA-256 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-256.
#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn compress256_64byte(state: &mut [u32; 8], blocks: &[GenericArray<u8, U64>]) {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    let p = blocks.as_ptr() as *const [u8; 64];
    let blocks = unsafe { core::slice::from_raw_parts(p, blocks.len()) };
    compress_64byte(state, blocks)
}
