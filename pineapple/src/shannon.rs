use shannon::Shannon;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecryptState {
    Header,
    Body,
}

pub enum DecryptResult {
    Header(u8, u16),
    Body(Vec<u8>),
}

pub struct ShannonCipher {
    encrypt_ctx: Shannon,
    encrypt_nonce: u32,

    decrypt_ctx: Shannon,
    decrypt_nonce: u32,
    decrypt_state: DecryptState,
}

impl ShannonCipher {
    pub fn new(encrypt_key: &[u8], decrypt_key: &[u8]) -> Self {
        ShannonCipher {
            encrypt_ctx: Shannon::new(encrypt_key),
            encrypt_nonce: 0,

            decrypt_ctx: Shannon::new(decrypt_key),
            decrypt_nonce: 0,
            decrypt_state: DecryptState::Header,
        }
    }

    pub fn encrypt(&mut self, packet: &mut Vec<u8>) {
        self.encrypt_ctx.nonce_u32(self.encrypt_nonce);
        self.encrypt_ctx.encrypt(packet);
        let mut hmac = vec![0; 4];
        self.encrypt_ctx.finish(&mut hmac);
        packet.append(&mut hmac);
        self.encrypt_nonce += 1;
    }

    pub fn decrypt(&mut self, input: &[u8]) -> DecryptResult {
        match self.decrypt_state {
            DecryptState::Header => {
                if input.len() != 3 {
                    panic!("Expected SPIRC header of length 3");
                }
                let mut data = [0; 3];
                data.copy_from_slice(input);

                self.decrypt_ctx.nonce_u32(self.decrypt_nonce);
                self.decrypt_ctx.decrypt(&mut data);
                let packet_type = data[0];
                let packet_len = u16::from_be_bytes(data[1..].try_into().unwrap());
                self.decrypt_state = DecryptState::Body;
                DecryptResult::Header(packet_type, packet_len)
            },
            DecryptState::Body => {
                if input.len() < 4 {
                    panic!("Expected body to contain HMAC");
                }
                let mut data = vec![];
                data.extend_from_slice(input);
                let expected_hmac: Vec<u8> = data.drain((data.len() - 4)..).collect();
                self.decrypt_ctx.decrypt(&mut data);
                let mut hmac = vec![0; 4];
                self.decrypt_ctx.finish(&mut hmac);
                self.decrypt_nonce += 1;
                self.decrypt_state = DecryptState::Header;
                if expected_hmac != hmac {
                    println!("Failed hmac test: {} != {}", hex::encode(&hmac), hex::encode(&expected_hmac));
                }
                DecryptResult::Body(data)
            },
        }
    }

    pub fn state(&self) -> DecryptState {
        self.decrypt_state
    }
}
