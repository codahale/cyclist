#![macro_use]

// TODO replace chunks with array iterators once the const generic train arrives

macro_rules! bytes_to_lanes {
    ($n:ty, $bytes:expr, $lanes:expr) => {
        for (b, n) in $bytes.chunks(core::mem::size_of::<$n>()).zip($lanes.iter_mut()) {
            *n = <$n>::from_le_bytes(b.try_into().unwrap());
        }
    };
}

macro_rules! lanes_to_bytes {
    ($n:ty, $lanes:expr, $bytes:expr) => {
        for (b, n) in $bytes.chunks_mut(core::mem::size_of::<$n>()).zip($lanes.iter()) {
            b.copy_from_slice(&n.to_le_bytes());
        }
    };
}

pub(crate) use bytes_to_lanes;
pub(crate) use lanes_to_bytes;
