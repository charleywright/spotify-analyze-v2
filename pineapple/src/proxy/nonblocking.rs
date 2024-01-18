use std::io::{ErrorKind, Read, Result, Write};

pub struct NonblockingReader {
    buffer: Vec<u8>,
    position: usize,
}

impl NonblockingReader {
    pub fn new(len: usize) -> Self {
        Self { buffer: vec![0; len], position: 0 }
    }

    pub fn read<S>(&mut self, source: &mut S) -> Result<usize>
    where
        S: Read + ?Sized,
    {
        match source.read(&mut self.buffer[self.position..]) {
            Ok(bytes_read) => {
                self.position += bytes_read;
                Ok(bytes_read)
            },
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(error),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn is_complete(&self) -> bool {
        self.position == self.buffer.len()
    }

    pub fn take(&mut self) -> Vec<u8> {
        self.position = 0;
        std::mem::take(&mut self.buffer)
    }
}

impl Default for NonblockingReader {
    fn default() -> Self {
        Self::new(0)
    }
}

pub struct NonblockingWriter {
    buffer: Vec<u8>,
    position: usize,
}

impl NonblockingWriter {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data, position: 0 }
    }

    pub fn write<T>(&mut self, target: &mut T) -> Result<usize>
    where
        T: Write + ?Sized,
    {
        match target.write(&self.buffer[self.position..]) {
            Ok(bytes_written) => {
                self.position += bytes_written;
                Ok(bytes_written)
            },
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(error),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn is_complete(&self) -> bool {
        self.position == self.buffer.len()
    }

    pub fn take(&mut self) -> Vec<u8> {
        self.position = 0;
        std::mem::take(&mut self.buffer)
    }
}

impl Default for NonblockingWriter {
    fn default() -> Self {
        Self::new(vec![])
    }
}
