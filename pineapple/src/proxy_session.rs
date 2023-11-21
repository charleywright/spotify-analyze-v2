use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;

use super::dh;
use dh::DiffieHellman;
use hmac::{Hmac, Mac};
use keyexchange::{APResponseMessage, ClientHello, ClientResponsePlaintext};
use num_bigint_dig::BigUint;
use pineapple_proto::keyexchange_old::{self as keyexchange, BuildInfo};
use protobuf::Message;
use rand::RngCore;
use rsa::Pkcs1v15Sign;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha1::{Digest, Sha1};

type HmacSha1 = Hmac<Sha1>;

// Pineapple's development key pair. TODO: Generate on startup and save locally
static OUR_PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCUj2epUddfOKQ2
GREoMq1JM90A9d0k5rkQ7dOMzdAKPXcwj5F8lkO+Kxd9Kk+vfds11OVBijMY0SwA
5gf008bUH8jW9SYWWepxMuza6w9VcNCYIVdrhxoDZCyM4TyOqAJ8ihua6cw2fZw/
vwLGf8FvRlRb5pUFbmsrZg5PrsLnSsFDh6T5ViTahz94mhNVHzJRkzYeqfLuOsjS
c9KBp2/76byH1329+9+R1YN203xGitHCcxxeoaCf+MSvy4x8hgmO18hRxy2sYTc7
hKhPenYXLYjzFn9zgziGCeHN4Yk9nZFhbLRfTPSTbahCokv28YIezAXSEP/Tn+kS
BToMDKaTAgMBAAECggEAFAPMDgJSN2h8qzMuXhGRyhp8LHxzalzRUygPh9lUrYSB
cd/t1HC0OMM6e2j/al/U8Eg6CN3zK2VG/en/6Wq8z2hm2RsXIgzEKrMXORlRLAwy
dkSLsBd4GDvfSq2vyHJ3P0smE/Vqx26d5fK4j4C30WOSyvziV+R7+NFbnT2o0ZtK
qRUDXf7FMx27amGXR6X90XjeuoqSwYHz3Vzod3zNeF6cv3thzg9tqJFZJePhVhc+
iLbthF7mdJuwv9p5r+zaidnYa1yajryO3cpte5qJm7Av81qQaQVTD10KbSlkd1VO
8s2db+CDgFaM979NFj5VeI53JEo53a5A4ChWk2e/zQKBgQDDT9oaymPdY6fgQVL7
70H6GLkSd2KcfwjXY/FXlTuoLv1sDt7T/SsLBivYdGWPHkuxjfQvUBOHPUXHhRDx
8rLqw6nZ8WZmX6rhZ+9rP47m6PcY32wJEu98vQXm7gQwN6qyI52RT3w63Dzc71l8
L52DQjV0mcZPZlOJQSv49V6iPQKBgQDCuKuvhuyA9lD/VJcUlB2hT5Pla8ZZuQk5
oaHXgOPYPCP+TTdPaRLxrzHCHE4zYX4J3dlk6IDTOHN7egyYwhX3YqGm181vTvEA
RTrUBF2V3xv2Z0w9W9C4Lz6VFg8kB9q2TJCpvOFXpg3GhKrb0wAYlRAAbrATXuZF
cthGtNEJDwKBgG3k4TiPxk8MQqoYt2OQBNR+0quERxT9GXFwB5ybGF0SS39ggppO
6cgjKcp5+6biif6We92fNc2zeS7BPX6Va3xSqaA6hr51d8WqYHk84uAkFtyE4dnd
MKlEBi0goXSr7byb842OZr0LrKc3eWc5t2vidgdseru0PK6O3/oNvbiVAoGBALgL
xHrLlI7wQe6UDZitxrPJe4jFLV1wv39xfn8qnDCt53ddlIHCVt2JMga+qkt2QqMg
xXHTMLB0EvMKkQ1xpUGGQDRqlQo4GyKeTNRIrAwULWHgkPcN6WGthgF0MCtmIRtd
kv5cQMGPekXA752G+fhCLDW8aUBl2lCaFEIAdfORAoGBAInElIhoNjDj7fs4DkX1
WlsLtObx2rJW9Nbyv76dI0BUvJQkOjAqLVNYdEJgtqgx+scfiTHPsQ+6WDN0B3kW
rtLxAVNM2/aQcBqPUFP8zLtzLVUMB4V27LKCPW3lezWhsltDXs6qGQtJ/F4fxw4S
BMOqg0LGsyoSgXSkuysOWen/
-----END PRIVATE KEY-----
"#;
static OUR_PUBLIC_KEY_MODULUS: [u8; 256] = [
    0x94, 0x8f, 0x67, 0xa9, 0x51, 0xd7, 0x5f, 0x38, 0xa4, 0x36, 0x19, 0x11, 0x28, 0x32, 0xad, 0x49, 0x33, 0xdd, 0x00,
    0xf5, 0xdd, 0x24, 0xe6, 0xb9, 0x10, 0xed, 0xd3, 0x8c, 0xcd, 0xd0, 0x0a, 0x3d, 0x77, 0x30, 0x8f, 0x91, 0x7c, 0x96,
    0x43, 0xbe, 0x2b, 0x17, 0x7d, 0x2a, 0x4f, 0xaf, 0x7d, 0xdb, 0x35, 0xd4, 0xe5, 0x41, 0x8a, 0x33, 0x18, 0xd1, 0x2c,
    0x00, 0xe6, 0x07, 0xf4, 0xd3, 0xc6, 0xd4, 0x1f, 0xc8, 0xd6, 0xf5, 0x26, 0x16, 0x59, 0xea, 0x71, 0x32, 0xec, 0xda,
    0xeb, 0x0f, 0x55, 0x70, 0xd0, 0x98, 0x21, 0x57, 0x6b, 0x87, 0x1a, 0x03, 0x64, 0x2c, 0x8c, 0xe1, 0x3c, 0x8e, 0xa8,
    0x02, 0x7c, 0x8a, 0x1b, 0x9a, 0xe9, 0xcc, 0x36, 0x7d, 0x9c, 0x3f, 0xbf, 0x02, 0xc6, 0x7f, 0xc1, 0x6f, 0x46, 0x54,
    0x5b, 0xe6, 0x95, 0x05, 0x6e, 0x6b, 0x2b, 0x66, 0x0e, 0x4f, 0xae, 0xc2, 0xe7, 0x4a, 0xc1, 0x43, 0x87, 0xa4, 0xf9,
    0x56, 0x24, 0xda, 0x87, 0x3f, 0x78, 0x9a, 0x13, 0x55, 0x1f, 0x32, 0x51, 0x93, 0x36, 0x1e, 0xa9, 0xf2, 0xee, 0x3a,
    0xc8, 0xd2, 0x73, 0xd2, 0x81, 0xa7, 0x6f, 0xfb, 0xe9, 0xbc, 0x87, 0xd7, 0x7d, 0xbd, 0xfb, 0xdf, 0x91, 0xd5, 0x83,
    0x76, 0xd3, 0x7c, 0x46, 0x8a, 0xd1, 0xc2, 0x73, 0x1c, 0x5e, 0xa1, 0xa0, 0x9f, 0xf8, 0xc4, 0xaf, 0xcb, 0x8c, 0x7c,
    0x86, 0x09, 0x8e, 0xd7, 0xc8, 0x51, 0xc7, 0x2d, 0xac, 0x61, 0x37, 0x3b, 0x84, 0xa8, 0x4f, 0x7a, 0x76, 0x17, 0x2d,
    0x88, 0xf3, 0x16, 0x7f, 0x73, 0x83, 0x38, 0x86, 0x09, 0xe1, 0xcd, 0xe1, 0x89, 0x3d, 0x9d, 0x91, 0x61, 0x6c, 0xb4,
    0x5f, 0x4c, 0xf4, 0x93, 0x6d, 0xa8, 0x42, 0xa2, 0x4b, 0xf6, 0xf1, 0x82, 0x1e, 0xcc, 0x05, 0xd2, 0x10, 0xff, 0xd3,
    0x9f, 0xe9, 0x12, 0x05, 0x3a, 0x0c, 0x0c, 0xa6, 0x93,
];
static OUR_PUBLIC_KEY_EXPONENT: usize = 65537;
static OUR_PUBLIC_KEY: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlI9nqVHXXzikNhkRKDKt
STPdAPXdJOa5EO3TjM3QCj13MI+RfJZDvisXfSpPr33bNdTlQYozGNEsAOYH9NPG
1B/I1vUmFlnqcTLs2usPVXDQmCFXa4caA2QsjOE8jqgCfIobmunMNn2cP78Cxn/B
b0ZUW+aVBW5rK2YOT67C50rBQ4ek+VYk2oc/eJoTVR8yUZM2Hqny7jrI0nPSgadv
++m8h9d9vfvfkdWDdtN8RorRwnMcXqGgn/jEr8uMfIYJjtfIUcctrGE3O4SoT3p2
Fy2I8xZ/c4M4hgnhzeGJPZ2RYWy0X0z0k22oQqJL9vGCHswF0hD/05/pEgU6DAym
kwIDAQAB
-----END PUBLIC KEY-----
"#;

// Spotify public key, we obviously don't know the private key
static SERVER_PUBLIC_KEY_MODULUS: [u8; 256] = [
    0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3, 0xbf, 0xbf, 0x86, 0x3d, 0xa1, 0x91, 0xc6,
    0xcc, 0x33, 0x6c, 0x93, 0xa1, 0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a, 0xf1, 0x80, 0xe7, 0xf6, 0x14, 0xd9,
    0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2, 0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b, 0xae, 0xdd, 0x14,
    0x02, 0xb1, 0x81, 0x55, 0x05, 0x61, 0x04, 0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02, 0x4a, 0xd4, 0xb2, 0x0c,
    0x00, 0x1f, 0x17, 0xed, 0xc2, 0x2f, 0xc4, 0x35, 0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2, 0xad, 0xd7, 0x2b, 0x0f, 0x9d,
    0xb3, 0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1, 0xfa, 0x62, 0x1e, 0xfb, 0x2c, 0x8d,
    0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47, 0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd, 0x24, 0xc2, 0xae, 0x25, 0x5b, 0x88, 0xff,
    0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31, 0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f,
    0xc9, 0x6b, 0x89, 0x9d, 0x95, 0x6b, 0xfc, 0x86, 0xd7, 0x4f, 0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9, 0xc3, 0x2d, 0x0d,
    0x32, 0xa5, 0xab, 0xcd, 0x05, 0x27, 0xe2, 0xf7, 0x10, 0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed,
    0x04, 0x9c, 0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2, 0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9, 0x48, 0x63, 0xec, 0xa1, 0xb6,
    0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3, 0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1, 0xc2, 0xba, 0x86, 0x30,
    0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c, 0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66, 0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1,
    0x1b, 0x13, 0x87, 0x3c, 0xd7, 0x19, 0xe6, 0x55, 0xbd,
];
static SERVER_PUBLIC_KEY_EXPONENT: usize = 65537;
static SERVER_PUBLIC_KEY: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOBGC//CMK/0a/7Dv7+G
PaGRxswzbJOhT7OwFhKsrGrxgOf2FNlCnb4uNGZD42LSMnoaDZI7rt0UArGBVQVh
BNUslqRMHswCStSyDAAfF+3CL8Q1Icjwy67SrdcrD52zxTIaKv5Z81oNrGjx+mIe
+yyNDLc5LZJH49c1Gm29JMKuJVuI/6tzKYoLzM0MWGcxiei9NIB4Sl/Ja4mdlWv8
htdPM6Z4F5bJwy0NMqWrzQUn4vcQo5YTxC+ZwCe/7QScPCdYBLayGfnBLwLpSGPs
obZCoJ1IJfizndDoavlITaHCuoYwQuqdswhsGQ5Is51m6wAGolruoRsThzzXGeZV
vQIDAQAB
-----END PUBLIC KEY-----
"#;

// Spotify currently only use one key
const SERVER_KEY_IDX: i32 = 0;

const SPIRC_MAGIC: [u8; 2] = [0x00, 0x04];

pub struct ProxySession {
    downstream_accumulator: Vec<u8>,
    downstream_dh: DiffieHellman,
    downstream_private_key: RsaPrivateKey,
    downstream_send_key: [u8; 32],
    downstream_recv_key: [u8; 32],
    downstream: TcpStream,

    upstream_accumulator: Vec<u8>,
    upstream_dh: DiffieHellman,
    upstream_public_key: RsaPublicKey,
    upstream_send_key: [u8; 32],
    upstream_recv_key: [u8; 32],
    upstream: TcpStream,
}

impl ProxySession {
    pub fn new(downstream: TcpStream, upstream: TcpStream) -> Self {
        let downstream_private_key =
            RsaPrivateKey::from_pkcs8_pem(OUR_PRIVATE_KEY).expect("Failed to parse pineapple private key");
        #[cfg(debug_assertions)]
        {
            let downstream_public_key =
                RsaPublicKey::from_public_key_pem(OUR_PUBLIC_KEY).expect("Failed to parse pineapple public key");
            assert_eq!(
                downstream_private_key.to_public_key(),
                downstream_public_key,
                "Expected our public keys to be equivalent #1"
            );
            let downstream_public_key_mod = BigUint::from_bytes_be(&OUR_PUBLIC_KEY_MODULUS);
            let downstream_public_key_exp = BigUint::from(OUR_PUBLIC_KEY_EXPONENT);
            let downstream_public_key =
                RsaPublicKey::new(downstream_public_key_mod, downstream_public_key_exp).unwrap();
            assert_eq!(
                downstream_private_key.to_public_key(),
                downstream_public_key,
                "Expected our public keys to be equivalent #2"
            );
        }

        let upstream_public_key =
            RsaPublicKey::from_public_key_pem(SERVER_PUBLIC_KEY).expect("Failed to parse Spotify public key");
        #[cfg(debug_assertions)]
        {
            let upstream_public_key_mod = BigUint::from_bytes_be(&SERVER_PUBLIC_KEY_MODULUS);
            let upstream_public_key_exp = BigUint::from(SERVER_PUBLIC_KEY_EXPONENT);
            let upstream_public_key2 = RsaPublicKey::new(upstream_public_key_mod, upstream_public_key_exp).unwrap();
            assert_eq!(
                upstream_public_key, upstream_public_key2,
                "Expected Spotify public keys to be equivalent"
            );
        }

        ProxySession {
            downstream,
            downstream_accumulator: Vec::<u8>::new(),
            downstream_dh: DiffieHellman::random(),
            downstream_private_key,
            downstream_send_key: [0; 32],
            downstream_recv_key: [0; 32],

            upstream,
            upstream_accumulator: Vec::<u8>::new(),
            upstream_dh: DiffieHellman::random(),
            upstream_public_key,
            upstream_send_key: [0; 32],
            upstream_recv_key: [0; 32],
        }
    }

    fn check_downstream_magic(&mut self) -> Result<(), Error> {
        let mut starting_magic_bytes = [0; 2];
        self.downstream.read_exact(&mut starting_magic_bytes)?;
        if starting_magic_bytes != SPIRC_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid magic bytes"));
        }
        self.downstream_accumulator.extend_from_slice(&starting_magic_bytes);
        Ok(())
    }

    fn read_downstream_client_hello(&mut self) -> Result<ClientHello, Error> {
        let mut client_hello_length_bytes = [0; 4];
        self.downstream.read_exact(&mut client_hello_length_bytes)?;
        let client_hello_length = u32::from_be_bytes(client_hello_length_bytes);
        self.downstream_accumulator.extend_from_slice(&client_hello_length_bytes);
        println!(
            "[D] Read ClientHello size {}, protobuf: {}",
            client_hello_length,
            client_hello_length - 6
        );

        let mut client_hello_bytes: Vec<u8> = vec![0; client_hello_length as usize - 6];
        self.downstream.read_exact(&mut client_hello_bytes)?;
        self.downstream_accumulator.extend(&client_hello_bytes);
        println!("[D] Read ClientHello: {}", hex::encode(&client_hello_bytes));
        ClientHello::parse_from_bytes(&client_hello_bytes).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    fn send_downstream_ap_response(&mut self) -> Result<(), Error> {
        let mut downstream_ap_response = APResponseMessage::default();
        downstream_ap_response
            .challenge
            .mut_or_insert_default()
            .fingerprint_challenge
            .mut_or_insert_default();
        downstream_ap_response.challenge.mut_or_insert_default().pow_challenge.mut_or_insert_default();
        downstream_ap_response.challenge.mut_or_insert_default().crypto_challenge.mut_or_insert_default();
        downstream_ap_response
            .challenge
            .mut_or_insert_default()
            .login_crypto_challenge
            .mut_or_insert_default()
            .diffie_hellman
            .mut_or_insert_default()
            .set_server_signature_key(SERVER_KEY_IDX);
        {
            let mut server_nonce = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut server_nonce);
            downstream_ap_response.challenge.mut_or_insert_default().set_server_nonce(server_nonce);
        }
        {
            let public_key_bytes = self.downstream_dh.public_bytes();
            let digest = Sha1::digest(&public_key_bytes);
            let padding = Pkcs1v15Sign::new::<Sha1>();
            let signature =
                self.downstream_private_key.sign(padding, &digest).expect("Failed to sign downstream DH key");
            downstream_ap_response
                .challenge
                .mut_or_insert_default()
                .login_crypto_challenge
                .mut_or_insert_default()
                .diffie_hellman
                .mut_or_insert_default()
                .set_gs(public_key_bytes);
            downstream_ap_response
                .challenge
                .mut_or_insert_default()
                .login_crypto_challenge
                .mut_or_insert_default()
                .diffie_hellman
                .mut_or_insert_default()
                .set_gs_signature(signature);
        }
        {
            let downstream_ap_response_len = downstream_ap_response.compute_size() as u32 + 4;
            let downstream_ap_response_len_bytes = downstream_ap_response_len.to_be_bytes();
            self.downstream
                .write_all(&downstream_ap_response_len_bytes)
                .expect("Failed to write APResponse length");
            self.downstream_accumulator.extend_from_slice(&downstream_ap_response_len_bytes);
            println!(
                "[D] Sent APResponse size {} protobuf {}",
                downstream_ap_response_len,
                downstream_ap_response_len - 4
            );

            let downstream_ap_response_bytes =
                downstream_ap_response.write_to_bytes().expect("Failed to serialize APResponse");
            self.downstream.write_all(&downstream_ap_response_bytes).expect("Failed to write APResponse");
            println!("[D] Sent APResponse {}", hex::encode(&downstream_ap_response_bytes));
            self.downstream_accumulator.extend(downstream_ap_response_bytes);
        }
        Ok(())
    }

    fn compute_downstream_keys(&mut self, client_key: &[u8]) -> Result<[u8; 20], Error> {
        self.downstream_dh.compute_shared(client_key);
        let shared_key = self.downstream_dh.shared_bytes();
        let mut data = vec![];
        for i in 1u8..6u8 {
            let mut hmac = HmacSha1::new_from_slice(&shared_key)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
            hmac.update(&self.downstream_accumulator);
            hmac.update(&[i]);
            data.extend_from_slice(&hmac.finalize().into_bytes());
        }
        let hmac_key = &data[0x00..0x14];
        let send_key = &data[0x14..0x34];
        let recv_key = &data[0x34..0x54];

        self.downstream_send_key.copy_from_slice(send_key);
        self.downstream_recv_key.copy_from_slice(recv_key);

        let mut hmac = HmacSha1::new_from_slice(hmac_key)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
        hmac.update(&self.downstream_accumulator);
        Ok(hmac.finalize().into_bytes().into())
    }

    fn read_downstream_client_response(&mut self) -> Result<ClientResponsePlaintext, Error> {
        let mut client_response_length_bytes = [0; 4];
        self.downstream.read_exact(&mut client_response_length_bytes)?;
        let client_response_length = u32::from_be_bytes(client_response_length_bytes);
        println!(
            "[D] Read ClientResponsePlaintext size {}, protobuf: {}",
            client_response_length,
            client_response_length - 4
        );

        let mut client_response_bytes: Vec<u8> = vec![0; client_response_length as usize - 4];
        self.downstream.read_exact(&mut client_response_bytes)?;
        println!("[D] Read ClientResponsePlaintext: {}", hex::encode(&client_response_bytes));
        ClientResponsePlaintext::parse_from_bytes(&client_response_bytes)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    fn send_upstream_client_hello(&mut self, build_info: protobuf::MessageField<BuildInfo>) -> Result<(), Error> {
        let mut client_hello = ClientHello {
            build_info,
            ..Default::default()
        };
        client_hello.cryptosuites_supported.push(keyexchange::Cryptosuite::CRYPTO_SUITE_SHANNON.into());
        {
            let mut nonce = vec![0; 16];
            rand::thread_rng().fill_bytes(&mut nonce);
            client_hello.set_client_nonce(nonce);
        }
        {
            // Make sure the accumulator is different even for identical messages
            // The server padding already makes sure of this, no harm doing it here too
            let mut padding = vec![0; 64];
            rand::thread_rng().fill_bytes(&mut padding);
            client_hello.set_padding(padding);
        }
        client_hello
            .login_crypto_hello
            .mut_or_insert_default()
            .diffie_hellman
            .mut_or_insert_default()
            .set_server_keys_known(1 << SERVER_KEY_IDX);
        client_hello
            .login_crypto_hello
            .mut_or_insert_default()
            .diffie_hellman
            .mut_or_insert_default()
            .set_gc(self.upstream_dh.public_bytes());

        self.upstream.write_all(&SPIRC_MAGIC)?;
        self.upstream_accumulator.extend_from_slice(&SPIRC_MAGIC);

        let client_hello_len = 2 + 4 + client_hello.compute_size() as u32;
        let client_hello_len_bytes = client_hello_len.to_be_bytes();
        self.upstream.write_all(&client_hello_len_bytes)?;
        self.upstream_accumulator.extend_from_slice(&client_hello_len_bytes);
        println!(
            "[U] Sent ClientHello size {} protobuf {}",
            client_hello_len,
            client_hello_len - 2 - 4
        );

        let client_hello_bytes = client_hello.write_to_bytes()?;
        self.upstream.write_all(&client_hello_bytes)?;
        println!("[U] Sent ClientHello {}", hex::encode(&client_hello_bytes));
        self.upstream_accumulator.extend(client_hello_bytes);
        Ok(())
    }

    fn read_upstream_ap_response(&mut self) -> Result<APResponseMessage, Error> {
        let mut ap_response_length_bytes = [0; 4];
        self.upstream.read_exact(&mut ap_response_length_bytes)?;
        let ap_response_length = u32::from_be_bytes(ap_response_length_bytes);
        self.upstream_accumulator.extend_from_slice(&ap_response_length_bytes);
        println!("[U] APResponseMessage protobuf size: {}", ap_response_length);
        let mut ap_response_bytes: Vec<u8> = vec![0; ap_response_length as usize - 4];
        self.upstream.read_exact(&mut ap_response_bytes)?;
        self.upstream_accumulator.extend(&ap_response_bytes);
        println!("[U] APResponseMessage: {}", hex::encode(&ap_response_bytes));
        APResponseMessage::parse_from_bytes(&ap_response_bytes).map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    fn validate_upstream_ap_response(&mut self, ap_response: &APResponseMessage) -> Result<[u8; 20], Error> {
        let remote_key = ap_response.challenge.login_crypto_challenge.diffie_hellman.gs();
        let signature = ap_response.challenge.login_crypto_challenge.diffie_hellman.gs_signature();
        let remote_key_hash = Sha1::digest(remote_key);
        let scheme = Pkcs1v15Sign::new::<Sha1>();
        self.upstream_public_key
            .verify(scheme, &remote_key_hash, signature)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "RSA Verification of upstream failed"))?;

        self.upstream_dh.compute_shared(remote_key);
        let shared_key = self.upstream_dh.shared_bytes();
        let mut data = vec![];
        for i in 1u8..6u8 {
            let mut hmac = HmacSha1::new_from_slice(&shared_key)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
            hmac.update(&self.upstream_accumulator);
            hmac.update(&[i]);
            data.extend_from_slice(&hmac.finalize().into_bytes());
        }
        let hmac_key = &data[0x00..0x14];
        let send_key = &data[0x14..0x34];
        let recv_key = &data[0x34..0x54];

        self.upstream_send_key.copy_from_slice(send_key);
        self.upstream_recv_key.copy_from_slice(recv_key);

        let mut hmac = HmacSha1::new_from_slice(hmac_key)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
        hmac.update(&self.upstream_accumulator);
        Ok(hmac.finalize().into_bytes().into())
    }

    fn send_upstream_client_response(&mut self, upstream_hmac: &[u8]) -> Result<(), Error> {
        let mut client_response = ClientResponsePlaintext::new();
        client_response
            .login_crypto_response
            .mut_or_insert_default()
            .diffie_hellman
            .mut_or_insert_default()
            .set_hmac(upstream_hmac.into());
        client_response.pow_response.mut_or_insert_default();
        client_response.crypto_response.mut_or_insert_default();
        let client_response_len = 4 + client_response.compute_size() as u32;
        let client_response_len_bytes = client_response_len.to_be_bytes();
        self.upstream.write_all(&client_response_len_bytes)?;
        println!(
            "[U] Sent ClientResponsePlaintext size {} protobuf {}",
            client_response_len,
            client_response_len - 4
        );

        let client_response_bytes = client_response.write_to_bytes()?;
        self.upstream.write_all(&client_response_bytes)?;
        println!("[U] Sent ClientResponsePlaintext {}", hex::encode(&client_response_bytes));
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), Error> {
        self.check_downstream_magic()?;
        let downstream_client_hello = self.read_downstream_client_hello()?;
        self.send_downstream_ap_response()?;
        let downstream_hmac =
            self.compute_downstream_keys(downstream_client_hello.login_crypto_hello.diffie_hellman.gc())?;
        let downstream_client_response = self.read_downstream_client_response()?;
        if downstream_client_response.login_crypto_response.diffie_hellman.hmac() != downstream_hmac {
            return Err(Error::new(ErrorKind::InvalidData, "Client has mismatched HMAC"));
        }
        println!(
            "[D] WE ARE ALL GOOD, SEND={} RECV={}",
            hex::encode(self.downstream_send_key),
            hex::encode(self.downstream_recv_key)
        );

        self.send_upstream_client_hello(downstream_client_hello.build_info)?;
        let upstream_ap_response = self.read_upstream_ap_response()?;
        let upstream_hmac = self.validate_upstream_ap_response(&upstream_ap_response)?;
        self.send_upstream_client_response(&upstream_hmac)?;
        println!(
            "[U] WE ARE ALL GOOD, SEND={} RECV={}",
            hex::encode(self.upstream_send_key),
            hex::encode(self.upstream_recv_key)
        );

        Ok(())
    }
}
