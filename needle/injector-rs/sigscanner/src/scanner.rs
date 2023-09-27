use std::collections::HashMap;

use super::Signature;

pub struct Scanner<'a> {
    signature: &'a Signature,
}

impl<'a> Scanner<'a> {
    pub fn new(signature: &'a Signature) -> Scanner<'a> {
        Self { signature }
    }

    pub fn scan(&self, data: &[u8]) -> Vec<usize> {
        self.signature.scan(data)
    }

    pub fn scan_with_offset(&self, data: &[u8], offset: usize) -> Vec<usize> {
        self.signature.scan_with_offset(data, offset)
    }
}

#[derive(Default)]
pub struct MultiScanner<'a> {
    signatures: Vec<&'a Signature>,
}

impl<'a> MultiScanner<'a> {
    pub fn add_signature(&mut self, signature: &'a Signature) {
        self.signatures.push(signature);
    }

    pub fn scan(&self, data: &[u8]) -> HashMap<&Signature, Vec<usize>> {
        let mut results = HashMap::new();

        for signature in &self.signatures {
            results.insert(signature.clone(), signature.scan(data));
        }

        results
    }

    pub fn scan_with_offset(&self, data: &[u8], offset: usize) -> HashMap<&Signature, Vec<usize>> {
        let mut results = HashMap::new();

        for signature in &self.signatures {
            results.insert(signature.clone(), signature.scan_with_offset(data, offset));
        }

        results
    }
}
