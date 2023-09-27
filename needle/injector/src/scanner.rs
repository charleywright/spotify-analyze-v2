#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MaskType {
    Wildcard,
    Byte,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    bytes: Vec<u8>,
    mask: Vec<MaskType>,
}

impl Signature {
    pub fn from_ida_style(signature: &str) -> Option<Self> {
        if signature.len() % 3 != 2 {
            return None;
        }

        let mut bytes: Vec<u8> = vec![];
        let mut mask: Vec<MaskType> = vec![];

        for part in signature.split_whitespace() {
            match part {
                "?" | "??" => {
                    bytes.push(0);
                    mask.push(MaskType::Wildcard);
                },
                _ => {
                    let byte = u8::from_str_radix(part, 16).ok()?;
                    bytes.push(byte);
                    mask.push(MaskType::Byte);
                },
            }
        }

        Some(Self { bytes, mask })
    }

    #[allow(dead_code)]
    pub fn from_code_style(bytes: &str, mask: &str) -> Option<Self> {
        if bytes.len() != mask.len() {
            return None;
        }
        if bytes.is_empty() {
            return None;
        }

        let bytes_vec = Vec::from(bytes.as_bytes());
        let mut mask_vec = vec![];
        for c in mask.chars() {
            match c {
                '?' => mask_vec.push(MaskType::Wildcard),
                'x' => mask_vec.push(MaskType::Byte),
                _ => return None,
            }
        }

        Some(Self {
            bytes: bytes_vec,
            mask: mask_vec,
        })
    }

    #[allow(dead_code)]
    pub fn scan(&self, data: &[u8]) -> Vec<usize> {
        self.scan_with_offset(data, 0)
    }

    pub fn scan_with_offset(&self, data: &[u8], offset: usize) -> Vec<usize> {
        let mut results = vec![];

        for i in 0..(data.len() - self.bytes.len()) {
            let mut found = true;
            for j in 0..self.bytes.len() {
                match self.mask[j] {
                    MaskType::Wildcard => continue,
                    MaskType::Byte => {
                        if data[i + j] != self.bytes[j] {
                            found = false;
                            break;
                        }
                    },
                }
            }
            if found {
                results.push(i + offset);
            }
        }

        results
    }

    #[allow(dead_code)]
    pub fn reverse_scan(&self, data: &[u8]) -> Vec<usize> {
        self.reverse_scan_with_offset(data, 0)
    }

    pub fn reverse_scan_with_offset(&self, data: &[u8], offset: usize) -> Vec<usize> {
        let mut results = vec![];

        for i in (0..(data.len() - self.bytes.len())).rev() {
            let mut found = true;
            for j in 0..self.bytes.len() {
                match self.mask[j] {
                    MaskType::Wildcard => continue,
                    MaskType::Byte => {
                        if data[i + j] != self.bytes[j] {
                            found = false;
                            break;
                        }
                    },
                }
            }
            if found {
                results.push(i + offset);
            }
        }

        results
    }
}
