#![allow(dead_code)]

use std::io::Write;

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub struct MmapBufWriter<W: ?Sized + Write> {
    inner: W,
}

impl<W: Write> MmapBufWriter<W> {
    pub fn new(inner: W) -> MmapBufWriter<W> {
        MmapBufWriter::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    pub fn with_capacity(_capacity: usize, inner: W) -> MmapBufWriter<W> {
        MmapBufWriter { inner }
    }
}
