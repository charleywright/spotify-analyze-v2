use std::{
    borrow::Cow,
    cell::RefCell,
    fmt::Display,
    io::{Error, ErrorKind, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    rc::Rc,
    time::{Duration, Instant},
};

use aes::cipher::{block_padding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use grain128::Grain128;
use hmac::{Hmac, Mac};
use keyexchange::{APResponseMessage, ClientHello, ClientResponsePlaintext};
use log::trace;
use mio::{event::Event, net::TcpStream, Interest, Registry, Token};
#[cfg(debug_assertions)]
use num_bigint_dig::BigUint;
use protobuf::Message;
use rand::{Rng, RngCore};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha1::{Digest, Sha1};

use super::{
    ap_resolver::ApResolver,
    dh::DiffieHellman,
    nonblocking::{NonblockingReader, NonblockingWriter},
    pcap_writer::PcapWriter,
    pow,
    proto::{authentication_old::ClientResponseEncrypted, keyexchange_old as keyexchange},
    shannon::{DecryptResult, ShannonCipher},
    token_manager::TokenManager,
};
use crate::pcap::{Interface, InterfaceDirection, PacketDirection};

type HmacSha1 = Hmac<Sha1>;
type Aes128CbcEncrypt = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDecrypt = cbc::Decryptor<aes::Aes128>;

// Pineapple's development key pair. TODO: Generate on startup and save locally
static OUR_PRIVATE_KEY: &str = r"
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
";
#[cfg(debug_assertions)]
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
#[cfg(debug_assertions)]
static OUR_PUBLIC_KEY_EXPONENT: usize = 65537;
#[cfg(debug_assertions)]
static OUR_PUBLIC_KEY: &str = r"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlI9nqVHXXzikNhkRKDKt
STPdAPXdJOa5EO3TjM3QCj13MI+RfJZDvisXfSpPr33bNdTlQYozGNEsAOYH9NPG
1B/I1vUmFlnqcTLs2usPVXDQmCFXa4caA2QsjOE8jqgCfIobmunMNn2cP78Cxn/B
b0ZUW+aVBW5rK2YOT67C50rBQ4ek+VYk2oc/eJoTVR8yUZM2Hqny7jrI0nPSgadv
++m8h9d9vfvfkdWDdtN8RorRwnMcXqGgn/jEr8uMfIYJjtfIUcctrGE3O4SoT3p2
Fy2I8xZ/c4M4hgnhzeGJPZ2RYWy0X0z0k22oQqJL9vGCHswF0hD/05/pEgU6DAym
kwIDAQAB
-----END PUBLIC KEY-----
";

// Spotify public key, we obviously don't know the private key
#[cfg(debug_assertions)]
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
#[cfg(debug_assertions)]
static SERVER_PUBLIC_KEY_EXPONENT: usize = 65537;
static SERVER_PUBLIC_KEY: &str = r"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOBGC//CMK/0a/7Dv7+G
PaGRxswzbJOhT7OwFhKsrGrxgOf2FNlCnb4uNGZD42LSMnoaDZI7rt0UArGBVQVh
BNUslqRMHswCStSyDAAfF+3CL8Q1Icjwy67SrdcrD52zxTIaKv5Z81oNrGjx+mIe
+yyNDLc5LZJH49c1Gm29JMKuJVuI/6tzKYoLzM0MWGcxiei9NIB4Sl/Ja4mdlWv8
htdPM6Z4F5bJwy0NMqWrzQUn4vcQo5YTxC+ZwCe/7QScPCdYBLayGfnBLwLpSGPs
obZCoJ1IJfizndDoavlITaHCuoYwQuqdswhsGQ5Is51m6wAGolruoRsThzzXGeZV
vQIDAQAB
-----END PUBLIC KEY-----
";

// Spotify currently only use one key
const SERVER_KEY_IDX: i32 = 0;
// First bytes sent to identify spirc
const SPIRC_MAGIC: [u8; 2] = [0x00, 0x04];
// Login packet type
const LOGIN_PACKET: u8 = 0xAB;
// How long to wait before marking an AP as invalid
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// TODO: Reduce allocations when decrypting then encrypting messages by using one buffer
// TODO: Properly support https://docs.rs/mio/latest/mio/struct.Poll.html#draining-readiness
//       Processing logic needs factoring out of handle_event() so it can be called from the proxy loop or recursively
pub struct ProxySession {
    pub downstream: TcpStream,
    pub downstream_addr: SocketAddr,
    pub downstream_token: Token,
    downstream_cipher: Option<ShannonCipher>,
    downstream_grain_key: Box<[u8]>,
    downstream_decrypt_packet_type: u8,
    downstream_decrypt_packet_len: u16,
    downstream_reader: NonblockingReader,
    downstream_writer: NonblockingWriter,
    downstream_iface: Option<Interface>,

    pub upstream: TcpStream,
    pub upstream_addr: SocketAddr,
    pub upstream_token: Token,
    upstream_cipher: Option<ShannonCipher>,
    upstream_grain_key: Box<[u8]>,
    upstream_decrypt_packet_type: u8,
    upstream_decrypt_packet_len: u16,
    upstream_reader: NonblockingReader,
    upstream_writer: NonblockingWriter,
    upstream_iface: Option<Interface>,

    pcap_writer: Rc<RefCell<PcapWriter>>,
    state: ProxySessionState,
}

impl ProxySession {
    pub fn create(
        downstream: TcpStream, token_manager: &mut TokenManager, ap_resolver: &mut ApResolver,
        pcap_writer: Rc<RefCell<PcapWriter>>,
    ) -> Result<Self, Error> {
        let downstream_token = token_manager.next();
        let upstream_token = token_manager.next();

        let Some(upstream_addr) = ap_resolver.get_resolved_ap() else {
            return Err(Error::other("Failed to resolve AP"));
        };
        let upstream = TcpStream::connect(upstream_addr)?;

        Ok(ProxySession {
            downstream,
            downstream_addr: "0.0.0.0:0".to_socket_addrs().unwrap().next().unwrap(),
            downstream_token,
            downstream_cipher: None,
            downstream_grain_key: vec![0; 16].into_boxed_slice(),
            downstream_decrypt_packet_type: 0,
            downstream_decrypt_packet_len: 0,
            downstream_reader: NonblockingReader::default(),
            downstream_writer: NonblockingWriter::default(),
            downstream_iface: None,

            upstream,
            upstream_addr,
            upstream_token,
            upstream_cipher: None,
            upstream_grain_key: vec![0; 16].into_boxed_slice(),
            upstream_reader: NonblockingReader::default(),
            upstream_writer: NonblockingWriter::default(),
            upstream_decrypt_packet_type: 0,
            upstream_decrypt_packet_len: 0,
            upstream_iface: None,

            pcap_writer,
            state: ProxySessionState::ReadDownstreamClientHello(Rc::new(RefCell::new(NegotiationData::new()))),
        })
    }
}

impl Display for ProxySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let default_ip = "0.0.0.0:0".to_socket_addrs().unwrap().next().unwrap();
        write!(f, "ProxySession {{ state: {} downstream: {} {:?} downstream_idx: {:?} upstream: {} {:?} upstream_send: {:?} }}",
            self.state,
            self.downstream.peer_addr().unwrap_or(default_ip), self.downstream_token,
            self.downstream_iface,
            self.upstream.peer_addr().unwrap_or(default_ip), self.upstream_token,
            self.upstream_iface
        )
    }
}

struct NegotiationData {
    downstream_accumulator: Vec<u8>,
    downstream_client_hello: ClientHello,
    downstream_ap_response: APResponseMessage,
    downstream_client_response_plaintext: ClientResponsePlaintext,
    downstream_client_response_encrypted: ClientResponseEncrypted,
    downstream_dh: DiffieHellman,
    downstream_private_key: RsaPrivateKey,

    upstream_timeout: Instant,
    upstream_accumulator: Vec<u8>,
    upstream_dh: DiffieHellman,
    upstream_ap_response: APResponseMessage,
    upstream_public_key: RsaPublicKey,
}

impl NegotiationData {
    pub fn new() -> Self {
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
            assert_eq!(upstream_public_key, upstream_public_key2, "Expected Spotify public keys to be equivalent");
        }

        NegotiationData {
            downstream_accumulator: Vec::<u8>::new(),
            downstream_client_hello: ClientHello::default(),
            downstream_ap_response: APResponseMessage::default(),
            downstream_client_response_plaintext: ClientResponsePlaintext::default(),
            downstream_client_response_encrypted: ClientResponseEncrypted::default(),
            downstream_dh: DiffieHellman::random(),
            downstream_private_key,

            upstream_timeout: Instant::now() + UPSTREAM_CONNECT_TIMEOUT,
            upstream_accumulator: Vec::<u8>::new(),
            upstream_dh: DiffieHellman::random(),
            upstream_ap_response: APResponseMessage::default(),
            upstream_public_key,
        }
    }
}

enum ProxySessionState {
    ReadDownstreamClientHello(Rc<RefCell<NegotiationData>>),
    ConnectingToUpstream(Rc<RefCell<NegotiationData>>),
    SendUpstreamClientHello(Rc<RefCell<NegotiationData>>),
    ReadUpstreamAPChallenge(Rc<RefCell<NegotiationData>>),
    SendDownstreamAPChallenge(Rc<RefCell<NegotiationData>>),
    ReadDownstreamClientResponsePlaintext(Rc<RefCell<NegotiationData>>),
    ReadDownstreamClientResponseEncrypted(Rc<RefCell<NegotiationData>>),
    SendUpstreamClientResponsePlaintext(Rc<RefCell<NegotiationData>>),
    SendUpstreamClientResponseEncrypted(Rc<RefCell<NegotiationData>>),
    Idle,
    ReadDownstream,
    SendUpstream,
    ReadUpstream,
    SendDownstream,
    Complete,
}

impl Display for ProxySessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::ReadDownstreamClientHello(_) => "ReadDownstreamClientHello",
            Self::ConnectingToUpstream(_) => "ConnectingToUpstream",
            Self::SendUpstreamClientHello(_) => "SendUpstreamClientHello",
            Self::ReadUpstreamAPChallenge(_) => "ReadUpstreamAPChallenge",
            Self::SendDownstreamAPChallenge(_) => "SendDownstreamAPChallenge",
            Self::ReadDownstreamClientResponsePlaintext(_) => "ReadDownstreamClientResponsePlaintext",
            Self::ReadDownstreamClientResponseEncrypted(_) => "ReadDownstreamClientResponseEncrypted",
            Self::SendUpstreamClientResponsePlaintext(_) => "SendUpstreamClientResponsePlaintext",
            Self::SendUpstreamClientResponseEncrypted(_) => "SendUpstreamClientResponseEncrypted",
            Self::Idle => "Idle",
            Self::ReadDownstream => "ReadDownstream",
            Self::SendUpstream => "SendUpstream",
            Self::ReadUpstream => "ReadUpstream",
            Self::SendDownstream => "SendDownstream",
            Self::Complete => "Complete",
        })
    }
}

pub enum ProxyTimeoutAdvice {
    KeepWaiting,
    StopChecking,
    TimedOut,
}

// Workaround to avoid rust-analyzer showing an error
// https://github.com/rust-lang/rust-analyzer/issues/15242
fn sha1_digest(plaintext: impl AsRef<[u8]>) -> Vec<u8> {
    let mut digest = vec![];
    digest.extend_from_slice(&<Sha1 as Digest>::digest(plaintext));
    digest
}

impl ProxySession {
    pub fn is_complete(&self) -> bool {
        matches!(self.state, ProxySessionState::Complete)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.downstream_addr
    }

    pub fn handle_event(&mut self, token: &Token, event: &Event) -> Result<(), Error> {
        if event.is_read_closed() || event.is_write_closed() {
            self.state = ProxySessionState::Complete;
            return Ok(());
        }

        match self.state {
            ProxySessionState::ReadDownstreamClientHello(ref state) => {
                if *token != self.downstream_token || !event.is_readable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();

                // Try to read magic
                if state_data.downstream_accumulator.is_empty() {
                    self.downstream_addr = self.downstream.peer_addr()?;
                    let mut pcap_writer = self.pcap_writer.borrow_mut();
                    self.downstream_iface = Some(
                        pcap_writer
                            .create_interface(InterfaceDirection::Downstream, self.downstream.peer_addr().unwrap()),
                    );

                    let mut magic_bytes = [0; SPIRC_MAGIC.len()];
                    if self.downstream.read_exact(&mut magic_bytes).is_err() {
                        // Not enough bytes to read
                        return Ok(());
                    }
                    if magic_bytes != SPIRC_MAGIC {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid SPIRC magic '{}'", hex::encode(magic_bytes)),
                        ));
                    }
                    pcap_writer.write_packet(
                        self.downstream_iface.unwrap(),
                        PacketDirection::Recv,
                        Cow::Borrowed(&magic_bytes),
                    );
                    state_data.downstream_accumulator.extend_from_slice(&magic_bytes);
                }

                // Try to read ClientHello length if not already
                if self.downstream_reader.is_empty() {
                    let mut client_hello_header = [0; 4];
                    let Ok(client_hello_header_bytes_read) = self.downstream.peek(&mut client_hello_header) else {
                        return Ok(());
                    };
                    if client_hello_header_bytes_read != client_hello_header.len() {
                        return Ok(());
                    }
                    let client_hello_len = u32::from_be_bytes(client_hello_header) as usize;
                    let client_hello_len = client_hello_len - SPIRC_MAGIC.len();
                    trace!(
                        "[{}] ClientHelloSize: {} Protobuf: {}",
                        self.downstream_addr,
                        client_hello_len,
                        client_hello_len - 4
                    );
                    self.downstream_reader = NonblockingReader::new(client_hello_len);
                }

                // We have read the magic and the header and know the size, but haven't read the whole ClientHello

                match self.downstream_reader.read(&mut self.downstream) {
                    Ok(bytes_read) => {
                        trace!("[{}] Read {bytes_read} bytes of ClientHello", self.downstream_addr);
                    },
                    Err(error) => {
                        // Write what we have, could be useful for debugging
                        self.pcap_writer.borrow_mut().write_packet(
                            self.downstream_iface.unwrap(),
                            PacketDirection::Recv,
                            Cow::Owned(self.downstream_reader.take()),
                        );
                        return Err(Error::new(error.kind(), ""));
                    },
                }

                // More to read
                if !self.downstream_reader.is_complete() {
                    return Ok(());
                }

                let mut client_hello_buffer = self.downstream_reader.take();
                self.pcap_writer.borrow_mut().write_packet(
                    self.downstream_iface.unwrap(),
                    PacketDirection::Recv,
                    Cow::Borrowed(&client_hello_buffer),
                );
                trace!("[{}] ClientHello: {}", self.downstream_addr, hex::encode(&client_hello_buffer));

                match ClientHello::parse_from_bytes(&client_hello_buffer[4..]) {
                    Ok(client_hello) => {
                        state_data.downstream_client_hello = client_hello;
                        state_data.downstream_accumulator.append(&mut client_hello_buffer);
                        drop(state_data);
                        self.state = ProxySessionState::ConnectingToUpstream(state.clone());
                        trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                        Ok(())
                    },
                    Err(parse_error) => {
                        Err(Error::new(ErrorKind::InvalidData, format!("Failed to parse ClientHello: {parse_error}")))
                    },
                }
            },
            ProxySessionState::ConnectingToUpstream(ref state) => {
                if *token != self.upstream_token {
                    return Ok(());
                }

                if let Ok(upstream_addr) = self.upstream.peer_addr() {
                    let mut pcap_writer = self.pcap_writer.borrow_mut();
                    self.upstream_iface = Some(
                        pcap_writer.create_interface(InterfaceDirection::Upstream, self.upstream.peer_addr().unwrap()),
                    );
                    trace!("[{}] Connected to upstream {upstream_addr}", self.downstream_addr);
                    self.state = ProxySessionState::SendUpstreamClientHello(state.clone());
                    trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                }

                Ok(())
            },
            ProxySessionState::SendUpstreamClientHello(ref state) => {
                if *token != self.upstream_token || !event.is_writable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();

                // Not created packet yet. Also not sent magic
                if self.upstream_writer.is_empty() {
                    if self.upstream.write_all(&SPIRC_MAGIC).is_err() {
                        return Err(Error::new(ErrorKind::Interrupted, "Failed to write SPIRC magic"));
                    }
                    self.pcap_writer.borrow_mut().write_packet(
                        self.upstream_iface.unwrap(),
                        PacketDirection::Send,
                        Cow::Borrowed(&SPIRC_MAGIC),
                    );
                    state_data.upstream_accumulator.extend_from_slice(&SPIRC_MAGIC);
                    trace!("[{}] Sent SPIRC magic to upstream", self.downstream_addr);

                    let mut client_hello = ClientHello::new();
                    client_hello.build_info.clone_from(&state_data.downstream_client_hello.build_info);
                    client_hello
                        .fingerprints_supported
                        .clone_from(&state_data.downstream_client_hello.fingerprints_supported);
                    client_hello
                        .cryptosuites_supported
                        .clone_from(&state_data.downstream_client_hello.cryptosuites_supported);
                    client_hello
                        .powschemes_supported
                        .clone_from(&state_data.downstream_client_hello.powschemes_supported);
                    {
                        rand::thread_rng().fill_bytes(&mut self.upstream_grain_key);
                        let mut nonce = vec![0; 16];
                        let mut nonce_encryptor = Grain128::keysetup(&self.upstream_grain_key, 128, 128);
                        nonce_encryptor.ivsetup(&[0; 16]);
                        nonce_encryptor.encrypt_bytes(&[0; 16], &mut nonce);
                        client_hello.set_client_nonce(nonce);
                    }
                    {
                        let padding_len: usize = rand::thread_rng().gen_range(1..256);
                        let mut padding = vec![0; padding_len];
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
                        .set_gc(state_data.upstream_dh.public_bytes());
                    client_hello.feature_set.clone_from(&state_data.downstream_client_hello.feature_set);

                    let client_hello_len = client_hello.compute_size() as usize + 4 + SPIRC_MAGIC.len();
                    let client_hello_len_bytes = (client_hello_len as u32).to_be_bytes();

                    let mut client_hello_buffer = vec![];
                    client_hello_buffer.reserve_exact(client_hello_len - SPIRC_MAGIC.len());
                    client_hello_buffer.extend_from_slice(&client_hello_len_bytes);
                    client_hello_buffer.extend_from_slice(&client_hello.write_to_bytes()?);
                    trace!(
                        "[{}] Sending {} bytes for ClientHello {}",
                        self.downstream_addr,
                        client_hello_len - SPIRC_MAGIC.len(),
                        hex::encode(&client_hello_buffer)
                    );
                    self.upstream_writer = NonblockingWriter::new(client_hello_buffer);
                }

                // ClientHello is serialized but we haven't finished sending it

                match self.upstream_writer.write(&mut self.upstream) {
                    Ok(bytes_written) => {
                        trace!("[{}] Written {bytes_written} bytes of ClientHello", self.downstream_addr);
                    },
                    Err(error) => {
                        self.pcap_writer.borrow_mut().write_packet(
                            self.upstream_iface.unwrap(),
                            PacketDirection::Send,
                            Cow::Owned(self.upstream_writer.take()),
                        );
                        return Err(error);
                    },
                }

                if !self.upstream_writer.is_complete() {
                    return Ok(());
                }

                let mut client_hello_buffer = self.upstream_writer.take();
                self.pcap_writer.borrow_mut().write_packet(
                    self.upstream_iface.unwrap(),
                    PacketDirection::Send,
                    Cow::Borrowed(&client_hello_buffer),
                );
                state_data.upstream_accumulator.append(&mut client_hello_buffer);
                drop(state_data);
                self.state = ProxySessionState::ReadUpstreamAPChallenge(state.clone());
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                Ok(())
            },
            ProxySessionState::ReadUpstreamAPChallenge(ref state) => {
                if *token != self.upstream_token || !event.is_readable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();

                // Try to read APResponse length if not already
                if self.upstream_reader.is_empty() {
                    let mut ap_response_header = [0; 4];
                    let Ok(ap_response_header_bytes_read) = self.upstream.peek(&mut ap_response_header) else {
                        return Ok(());
                    };
                    if ap_response_header_bytes_read != ap_response_header.len() {
                        return Ok(());
                    }
                    let ap_response_len = u32::from_be_bytes(ap_response_header) as usize;
                    trace!(
                        "[{}] APResponseSize: {} Protobuf: {}",
                        self.downstream_addr,
                        ap_response_len,
                        ap_response_len - 4
                    );
                    self.upstream_reader = NonblockingReader::new(ap_response_len);
                }

                // We know the size but haven't finished reading yet

                match self.upstream_reader.read(&mut self.upstream) {
                    Ok(bytes_read) => {
                        trace!("[{}] Read {bytes_read} bytes of APResponse", self.downstream_addr);
                    },
                    Err(error) => {
                        self.pcap_writer.borrow_mut().write_packet(
                            self.upstream_iface.unwrap(),
                            PacketDirection::Recv,
                            Cow::Owned(self.upstream_reader.take()),
                        );
                        return Err(error);
                    },
                }

                // More to read
                if !self.upstream_reader.is_complete() {
                    return Ok(());
                }

                let mut ap_response_buffer = self.upstream_reader.take();
                self.pcap_writer.borrow_mut().write_packet(
                    self.upstream_iface.unwrap(),
                    PacketDirection::Recv,
                    Cow::Borrowed(&ap_response_buffer),
                );
                trace!("[{}] APResponse: {}", self.downstream_addr, hex::encode(&ap_response_buffer));

                match APResponseMessage::parse_from_bytes(&ap_response_buffer[4..]) {
                    Ok(ap_response) => {
                        if ap_response.challenge.is_none() &&
                            ap_response.upgrade.is_none() &&
                            ap_response.login_failed.is_none()
                        {
                            return Err(Error::new(ErrorKind::InvalidData, "Upstream AP returned invalid APResponse"));
                        }

                        state_data.upstream_ap_response = ap_response;
                        state_data.upstream_accumulator.append(&mut ap_response_buffer);
                        drop(state_data);
                        self.state = ProxySessionState::SendDownstreamAPChallenge(state.clone());
                        trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                        Ok(())
                    },
                    Err(parse_error) => Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Failed to parse APResponseMessage: {parse_error}"),
                    )),
                }
            },
            ProxySessionState::SendDownstreamAPChallenge(ref state) => {
                if *token != self.downstream_token || !event.is_writable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();

                // Not created packet yet
                if self.downstream_writer.is_empty() {
                    let mut ap_response = APResponseMessage::default();
                    if ap_response.upgrade.is_some() {
                        ap_response.upgrade.clone_from(&state_data.upstream_ap_response.upgrade);
                    } else if ap_response.login_failed.is_some() {
                        ap_response.login_failed.clone_from(&state_data.upstream_ap_response.login_failed);
                    } else if let Some(upstream_ap_challenge) = state_data.upstream_ap_response.challenge.as_ref() {
                        // This is an assumption. The client nonce generation is part of the grain challenge so this
                        // may not be random however it isn't used by the client (as of 8.8.96.364)
                        let mut server_nonce = vec![0; 16];
                        rand::thread_rng().fill_bytes(&mut server_nonce);
                        ap_response.challenge.mut_or_insert_default().set_server_nonce(server_nonce);

                        let padding_len = rand::thread_rng().gen_range(1..255);
                        let mut padding = vec![0; padding_len];
                        rand::thread_rng().fill_bytes(&mut padding);
                        ap_response.challenge.mut_or_insert_default().set_padding(padding);

                        ap_response.challenge.mut_or_insert_default().login_crypto_challenge.mut_or_insert_default();
                        if upstream_ap_challenge.login_crypto_challenge.diffie_hellman.is_some() {
                            let diffie_hellman_challenge = ap_response
                                .challenge
                                .mut_or_insert_default()
                                .login_crypto_challenge
                                .mut_or_insert_default()
                                .diffie_hellman
                                .mut_or_insert_default();
                            let public_key_bytes = state_data.downstream_dh.public_bytes();
                            let digest = sha1_digest(&public_key_bytes);
                            let padding = Pkcs1v15Sign::new::<Sha1>();
                            let signature = state_data
                                .downstream_private_key
                                .sign(padding, &digest)
                                .expect("Failed to sign downstream DH key");
                            diffie_hellman_challenge.set_server_signature_key(SERVER_KEY_IDX);
                            diffie_hellman_challenge.set_gs(public_key_bytes);
                            diffie_hellman_challenge.set_gs_signature(signature);
                        } else {
                            // When solving the diffie hellman challenge we also get the shannon keys
                            // There doesn't appear to be another way to obtain them, so consider this fatal
                            unimplemented!(
                                "Upstream didn't send a diffie hellman challenge, please open an issue on Github"
                            );
                        }

                        ap_response.challenge.mut_or_insert_default().fingerprint_challenge.mut_or_insert_default();
                        if upstream_ap_challenge.fingerprint_challenge.grain.is_some() {
                            // Same as the server nonce, this is an assumption. There doesn't appear to be any reason
                            // for this not to be random but we will likely never know for sure
                            let grain_challenge = ap_response
                                .challenge
                                .mut_or_insert_default()
                                .fingerprint_challenge
                                .mut_or_insert_default()
                                .grain
                                .mut_or_insert_default();
                            let mut key_exchange_key = vec![0; 16];
                            rand::thread_rng().fill_bytes(&mut key_exchange_key);
                            grain_challenge.set_kek(key_exchange_key);
                        }
                        if upstream_ap_challenge.fingerprint_challenge.hmac_ripemd.is_some() {
                            unimplemented!(
                                "Upstream sent FingerprintHmacRipeMDChallenge, please open an issue on Github"
                            );
                        }

                        ap_response.challenge.mut_or_insert_default().pow_challenge.mut_or_insert_default();
                        if upstream_ap_challenge.pow_challenge.hash_cash.is_some() {
                            let hash_cash_challenge = ap_response
                                .challenge
                                .mut_or_insert_default()
                                .pow_challenge
                                .mut_or_insert_default()
                                .hash_cash
                                .mut_or_insert_default();

                            let mut prefix = vec![0; 16];
                            rand::thread_rng().fill_bytes(&mut prefix);
                            let length = 14;
                            let target = rand::thread_rng().gen_range(1..65535);
                            hash_cash_challenge.set_prefix(prefix);
                            hash_cash_challenge.set_length(length);
                            hash_cash_challenge.set_target(target);
                        }

                        ap_response.challenge.mut_or_insert_default().crypto_challenge.mut_or_insert_default();
                        if upstream_ap_challenge.crypto_challenge.shannon.is_some() {
                            // Spotify send an empty message
                            ap_response
                                .challenge
                                .mut_or_insert_default()
                                .crypto_challenge
                                .mut_or_insert_default()
                                .shannon
                                .mut_or_insert_default();
                        }
                        if upstream_ap_challenge.crypto_challenge.rc4_sha1_hmac.is_some() {
                            unimplemented!("Upstream sent CryptoRc4Sha1HmacChallenge, please open an issue on Github");
                        }
                    }

                    let ap_response_len = ap_response.compute_size() as u32 + 4;
                    let ap_response_len_bytes = ap_response_len.to_be_bytes();
                    let mut ap_response_buffer = vec![];
                    ap_response_buffer.reserve_exact(ap_response_len as usize);
                    ap_response_buffer.extend_from_slice(&ap_response_len_bytes);
                    ap_response_buffer.extend_from_slice(&ap_response.write_to_bytes()?);
                    state_data.downstream_ap_response = ap_response;
                    trace!(
                        "[{}] Sending {} bytes for APResponseMessage {}",
                        self.downstream_addr,
                        ap_response_len,
                        hex::encode(&ap_response_buffer)
                    );
                    self.downstream_writer = NonblockingWriter::new(ap_response_buffer);
                }

                // APResponseMessage is serialized but we haven't finished sending it

                match self.downstream_writer.write(&mut self.downstream) {
                    Ok(bytes_written) => {
                        trace!("[{}] Written {bytes_written} bytes of APResponseMessage", self.downstream_addr);
                    },
                    Err(error) => {
                        self.pcap_writer.borrow_mut().write_packet(
                            self.downstream_iface.unwrap(),
                            PacketDirection::Send,
                            Cow::Owned(self.downstream_writer.take()),
                        );
                        return Err(error);
                    },
                }

                if !self.downstream_writer.is_complete() {
                    return Ok(());
                }

                let mut ap_response_buffer = self.downstream_writer.take();
                self.pcap_writer.borrow_mut().write_packet(
                    self.downstream_iface.unwrap(),
                    PacketDirection::Send,
                    Cow::Borrowed(&ap_response_buffer),
                );
                state_data.downstream_accumulator.append(&mut ap_response_buffer);
                drop(state_data);
                self.state = ProxySessionState::ReadDownstreamClientResponsePlaintext(state.clone());
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                Ok(())
            },
            ProxySessionState::ReadDownstreamClientResponsePlaintext(ref state) => {
                if *token != self.downstream_token || !event.is_readable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();

                if self.downstream_reader.is_empty() {
                    let mut client_response_header = [0; 4];
                    let Ok(client_response_header_bytes_read) = self.downstream.peek(&mut client_response_header)
                    else {
                        return Ok(());
                    };
                    if client_response_header_bytes_read != client_response_header.len() {
                        return Ok(());
                    }
                    let client_response_len = u32::from_be_bytes(client_response_header) as usize;
                    trace!(
                        "[{}] ClientResponsePlaintextSize: {} Protobuf: {}",
                        self.downstream_addr,
                        client_response_len,
                        client_response_len - 4
                    );
                    self.downstream_reader = NonblockingReader::new(client_response_len);
                }

                match self.downstream_reader.read(&mut self.downstream) {
                    Ok(bytes_read) => {
                        trace!("[{}] Read {bytes_read} bytes of ClientResponsePlaintext", self.downstream_addr);
                    },
                    Err(error) => {
                        self.pcap_writer.borrow_mut().write_packet(
                            self.downstream_iface.unwrap(),
                            PacketDirection::Recv,
                            Cow::Owned(self.downstream_reader.take()),
                        );
                        return Err(error);
                    },
                }

                if !self.downstream_reader.is_complete() {
                    return Ok(());
                }

                let client_response_buffer = self.downstream_reader.take();
                self.pcap_writer.borrow_mut().write_packet(
                    self.downstream_iface.unwrap(),
                    PacketDirection::Recv,
                    Cow::Borrowed(&client_response_buffer),
                );
                trace!("[{}] ClientResponsePlaintext: {}", self.downstream_addr, hex::encode(&client_response_buffer));

                match ClientResponsePlaintext::parse_from_bytes(&client_response_buffer[4..]) {
                    Ok(client_response) => {
                        state_data.downstream_client_response_plaintext = client_response;
                    },
                    Err(parse_error) => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("Failed to parse ClientResponsePlaintext: {parse_error}"),
                        ))
                    },
                }

                // Check the client's solutions to challenges. ap.spotify.com does not consider it an error if the
                // client doesn't provide a solution to a challenge given by the server, so we are not going to enforce
                // them either.

                if state_data.downstream_client_response_plaintext.login_crypto_response.is_some() &&
                    state_data.downstream_client_response_plaintext.login_crypto_response.diffie_hellman.is_some()
                {
                    let downstream_public_key =
                        Vec::from(state_data.downstream_client_hello.login_crypto_hello.diffie_hellman.gc());
                    state_data.downstream_dh.compute_shared(&downstream_public_key);
                    let shared_key = state_data.downstream_dh.shared_bytes();
                    let mut data = vec![];
                    for i in 1u8..6u8 {
                        let mut hmac = HmacSha1::new_from_slice(&shared_key)
                            .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
                        hmac.update(&state_data.downstream_accumulator);
                        hmac.update(&[i]);
                        data.extend_from_slice(&hmac.finalize().into_bytes());
                    }
                    let hmac_key = &data[0x00..0x14];
                    let downstream_key = &data[0x14..0x34];
                    let proxy_key = &data[0x34..0x54];
                    self.downstream_cipher = ShannonCipher::new(proxy_key, downstream_key).into();
                    let mut computed_hmac = HmacSha1::new_from_slice(hmac_key)
                        .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
                    computed_hmac.update(&state_data.downstream_accumulator);
                    let computed_hmac: [u8; 20] = computed_hmac.finalize().into_bytes().into();
                    let computed_hmac = Vec::<u8>::from(computed_hmac);

                    let downstream_hmac = Vec::from(
                        state_data.downstream_client_response_plaintext.login_crypto_response.diffie_hellman.hmac(),
                    );

                    if computed_hmac != downstream_hmac {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "Downstream sent invalid hmac, computed: {} downstream: {}",
                                hex::encode(&computed_hmac),
                                hex::encode(&downstream_hmac)
                            ),
                        ));
                    }

                    trace!(
                        "[{}] Computed hmac: {} downstream key: {} proxy key: {}",
                        self.downstream_addr,
                        hex::encode(&computed_hmac),
                        hex::encode(downstream_key),
                        hex::encode(proxy_key)
                    );
                }

                if state_data.downstream_client_response_plaintext.pow_response.hash_cash.is_some() {
                    let Some(challenge) = state_data.downstream_ap_response.challenge.pow_challenge.hash_cash.as_ref()
                    else {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "Client sent a PoW HashCash response when no challenge was sent",
                        ));
                    };
                    let computed_suffix = pow::solve_hashcash(&state_data.downstream_accumulator, challenge)?;
                    let downstream_suffix =
                        Vec::from(state_data.downstream_client_response_plaintext.pow_response.hash_cash.hash_suffix());
                    trace!(
                        "[{}] Downstream hash cash solution - suffix: {} prefix: {} length: {} target: {} accumulator: {}",
                        self.downstream_addr,
                        hex::encode(&computed_suffix),
                        hex::encode(challenge.prefix()),
                        challenge.length(),
                        challenge.target(),
                        hex::encode(&state_data.downstream_accumulator)
                    );
                    if computed_suffix != downstream_suffix {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "Hash cash solution mismatch, proxy: {} downstream: {}",
                                hex::encode(&computed_suffix),
                                hex::encode(&downstream_suffix)
                            ),
                        ));
                    }
                }

                if state_data.downstream_client_response_plaintext.crypto_response.is_some() {
                    if state_data.downstream_client_response_plaintext.crypto_response.shannon.is_some() {
                        trace!("[{}] Downstream sent shannon crypto response solution", self.downstream_addr);
                    }
                    if state_data.downstream_client_response_plaintext.crypto_response.rc4_sha1_hmac.is_some() {
                        trace!("[{}] Downstream sent RC4 SHA1 crypto response solution", self.downstream_addr);
                    }
                }

                drop(state_data);
                self.state = ProxySessionState::ReadDownstreamClientResponseEncrypted(state.clone());
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                Ok(())
            },
            ProxySessionState::ReadDownstreamClientResponseEncrypted(ref state) => {
                if *token != self.downstream_token || !event.is_readable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();
                let Some(downstream_cipher) = self.downstream_cipher.as_mut() else {
                    return Err(Error::other("No downstream cipher while trying to read ClientResponseEncrypted"));
                };

                if self.downstream_reader.is_empty() {
                    let mut client_response_header = [0; 3];
                    self.downstream.read_exact(&mut client_response_header)?;
                    let DecryptResult::Header(packet_type, packet_len) =
                        downstream_cipher.decrypt(&client_response_header)
                    else {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Failed to decrypt header for ClientResponseEncrypted",
                        ));
                    };

                    if packet_type != LOGIN_PACKET {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("Expected {LOGIN_PACKET} for ClientResponseEncrypted, got {packet_type:#02X}"),
                        ));
                    }
                    let packet_len = packet_len as usize + 4; // 4 byte MAC after encrypted bytes

                    trace!(
                        "[{}] ClientResponseEncrypted - Type: {:#02X} Length: {}",
                        self.downstream_addr,
                        packet_type,
                        packet_len
                    );
                    self.downstream_reader = NonblockingReader::new(packet_len);
                }

                match self.downstream_reader.read(&mut self.downstream) {
                    Ok(bytes_read) => {
                        trace!("[{}] Read {bytes_read} bytes of ClientResponseEncrypted", self.downstream_addr);
                    },
                    Err(error) => return Err(error),
                }

                // More to read
                if !self.downstream_reader.is_complete() {
                    return Ok(());
                }

                // Decrypt body, MAC isn't encrypted since we couldn't verify an unsuccessful decrypt
                let DecryptResult::Body(packet) = downstream_cipher.decrypt(&self.downstream_reader.take()) else {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Failed to decrypt packet for ClientResponseEncrypted",
                    ));
                };
                let packet = {
                    let mut tmp = Vec::with_capacity(1 + 2 + packet.len());
                    tmp.push(LOGIN_PACKET);
                    tmp.extend_from_slice(&u16::to_be_bytes(packet.len() as u16));
                    tmp.extend(packet);
                    tmp
                };
                trace!("[{}] ClientResponseEncrypted: {}", self.downstream_addr, hex::encode(&packet));
                self.pcap_writer.borrow_mut().write_packet(
                    self.downstream_iface.unwrap(),
                    PacketDirection::Recv,
                    Cow::Borrowed(&packet),
                );

                match ClientResponseEncrypted::parse_from_bytes(&packet[3..]) {
                    Ok(client_response) => {
                        state_data.downstream_client_response_encrypted = client_response;
                    },
                    Err(parse_error) => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("Failed to parse ClientResponseEncrypted: {parse_error}"),
                        ))
                    },
                }

                if state_data.downstream_client_response_encrypted.fingerprint_response.is_some() {
                    if state_data.downstream_client_response_encrypted.fingerprint_response.grain.is_some() {
                        // Get SHA1 of accumulator
                        let accumulator_hash = sha1_digest(&state_data.downstream_accumulator);

                        // Encrypt hash
                        let kek = state_data.downstream_ap_response.challenge.fingerprint_challenge.grain.kek();
                        let mut hash_encryptor = Grain128::keysetup(kek, 128, 128);
                        hash_encryptor.ivsetup(&[0; 16]);
                        let mut encrypted_hash = [0; 16];
                        hash_encryptor.encrypt_bytes(&accumulator_hash[0..16], &mut encrypted_hash);

                        // Decrypt `encrypted_key` using encrypted accumulator hash
                        let encrypted_key =
                            state_data.downstream_client_response_encrypted.fingerprint_response.grain.encrypted_key();
                        let Ok(grain_key) = Aes128CbcDecrypt::new(&encrypted_hash.into(), &[0u8; 16].into())
                            .decrypt_padded_vec_mut::<block_padding::NoPadding>(encrypted_key)
                        else {
                            return Err(Error::other("Failed to decrypt grain key"));
                        };

                        // Verify the key by decrypting client_nonce
                        let client_nonce = state_data.downstream_client_hello.client_nonce();
                        let mut client_nonce_decryptor = Grain128::keysetup(&grain_key, 128, 128);
                        client_nonce_decryptor.ivsetup(&[0; 16]);
                        let mut decrypted_client_nonce = [0; 16];
                        client_nonce_decryptor.decrypt_bytes(client_nonce, &mut decrypted_client_nonce);
                        if decrypted_client_nonce != [0; 16] {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                format!(
                                    "Expected decrypted client_nonce to be all zeroes, got {}",
                                    hex::encode(decrypted_client_nonce)
                                ),
                            ));
                        }

                        // All good
                        self.downstream_grain_key.copy_from_slice(&grain_key);
                        trace!("[{}] Verified downstream grain key {}", self.downstream_addr, hex::encode(&grain_key));
                    }
                    if state_data.downstream_client_response_encrypted.fingerprint_response.hmac_ripemd.is_some() {
                        unimplemented!("HMAC RipeMD is unknown, please open an issue on Github");
                    }
                }

                drop(state_data);
                self.state = ProxySessionState::SendUpstreamClientResponsePlaintext(state.clone());
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                Ok(())
            },
            ProxySessionState::SendUpstreamClientResponsePlaintext(ref state) => {
                if *token != self.upstream_token || !event.is_writable() {
                    return Ok(());
                }

                let mut state_data = state.borrow_mut();

                if self.upstream_writer.is_empty() {
                    let mut client_response = ClientResponsePlaintext::new();

                    client_response.login_crypto_response.mut_or_insert_default();
                    if let Some(login_crypto_challenge) =
                        state_data.upstream_ap_response.challenge.login_crypto_challenge.as_ref()
                    {
                        if let Some(diffie_hellman_challenge) = login_crypto_challenge.diffie_hellman.as_ref() {
                            let remote_key = Vec::from(diffie_hellman_challenge.gs());
                            let signature = diffie_hellman_challenge.gs_signature();
                            let remote_key_hash = sha1_digest(&remote_key);
                            let scheme = Pkcs1v15Sign::new::<Sha1>();
                            state_data.upstream_public_key.verify(scheme, &remote_key_hash, signature).map_err(
                                |_| Error::new(ErrorKind::InvalidData, "RSA Verification of upstream failed"),
                            )?;

                            state_data.upstream_dh.compute_shared(&remote_key);
                            let shared_key = state_data.upstream_dh.shared_bytes();
                            let mut data = vec![];
                            for i in 1u8..6u8 {
                                let mut hmac = HmacSha1::new_from_slice(&shared_key)
                                    .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
                                hmac.update(&state_data.upstream_accumulator);
                                hmac.update(&[i]);
                                data.extend_from_slice(&hmac.finalize().into_bytes());
                            }
                            let hmac_key = &data[0x00..0x14];
                            let proxy_key = &data[0x14..0x34];
                            let upstream_key = &data[0x34..0x54];
                            self.upstream_cipher = ShannonCipher::new(proxy_key, upstream_key).into();
                            let mut computed_hmac = HmacSha1::new_from_slice(hmac_key)
                                .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to create HMAC"))?;
                            computed_hmac.update(&state_data.upstream_accumulator);
                            let computed_hmac: [u8; 20] = computed_hmac.finalize().into_bytes().into();
                            let computed_hmac = Vec::<u8>::from(computed_hmac);

                            trace!(
                                "[{}] Computed hmac: {} Proxy key: {} Upstream key: {} ",
                                self.downstream_addr,
                                hex::encode(&computed_hmac),
                                hex::encode(proxy_key),
                                hex::encode(upstream_key)
                            );

                            client_response
                                .login_crypto_response
                                .mut_or_insert_default()
                                .diffie_hellman
                                .mut_or_insert_default()
                                .set_hmac(computed_hmac);
                        }
                    }

                    client_response.pow_response.mut_or_insert_default();
                    if let Some(pow_challenge) = state_data.upstream_ap_response.challenge.pow_challenge.as_ref() {
                        if let Some(hash_cash_challenge) = pow_challenge.hash_cash.as_ref() {
                            let suffix = pow::solve_hashcash(&state_data.upstream_accumulator, hash_cash_challenge)?;
                            trace!(
                                "[{}] Upstream hash cash solution - suffix: {} prefix: {} length: {} target: {} accumulator: {}",
                                self.downstream_addr,
                                hex::encode(&suffix),
                                hex::encode(hash_cash_challenge.prefix()),
                                hash_cash_challenge.length(),
                                hash_cash_challenge.target(),
                                hex::encode(&state_data.upstream_accumulator)
                            );
                            client_response
                                .pow_response
                                .mut_or_insert_default()
                                .hash_cash
                                .mut_or_insert_default()
                                .set_hash_suffix(suffix);
                        }
                    }

                    client_response.crypto_response.mut_or_insert_default();
                    if let Some(crypto_challenge) = state_data.upstream_ap_response.challenge.crypto_challenge.as_ref()
                    {
                        if let Some(_shannon_challenge) = crypto_challenge.shannon.as_ref() {
                            client_response.crypto_response.mut_or_insert_default().shannon.mut_or_insert_default();
                        }
                        if let Some(_rc4_sha1_hmac_challenge) = crypto_challenge.rc4_sha1_hmac.as_ref() {
                            unimplemented!("RC4_SHA1_HMAC crypto challenge is unknown, please open an issue on Github");
                        }
                    }

                    let client_response_len = client_response.compute_size() as u32 + 4;
                    let client_response_len_bytes = client_response_len.to_be_bytes();
                    let mut client_response_buffer = vec![];
                    client_response_buffer.reserve_exact(client_response_len as usize);
                    client_response_buffer.extend_from_slice(&client_response_len_bytes);
                    client_response_buffer.extend_from_slice(&client_response.write_to_bytes()?);
                    trace!(
                        "[{}] Sending {} bytes for ClientResponsePlaintext {}",
                        self.downstream_addr,
                        client_response_len,
                        hex::encode(&client_response_buffer)
                    );
                    self.upstream_writer = NonblockingWriter::new(client_response_buffer);
                }

                match self.upstream_writer.write(&mut self.upstream) {
                    Ok(bytes_written) => {
                        trace!("[{}] Written {bytes_written} bytes of ClientResponsePlaintext", self.downstream_addr,);
                    },
                    Err(error) => {
                        self.pcap_writer.borrow_mut().write_packet(
                            self.upstream_iface.unwrap(),
                            PacketDirection::Send,
                            Cow::Owned(self.upstream_writer.take()),
                        );
                        return Err(error);
                    },
                }

                if !self.upstream_writer.is_complete() {
                    return Ok(());
                }

                self.pcap_writer.borrow_mut().write_packet(
                    self.upstream_iface.unwrap(),
                    PacketDirection::Send,
                    Cow::Owned(self.upstream_writer.take()),
                );
                drop(state_data);
                self.state = ProxySessionState::SendUpstreamClientResponseEncrypted(state.clone());
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);

                Ok(())
            },
            ProxySessionState::SendUpstreamClientResponseEncrypted(ref state) => {
                if *token != self.upstream_token || !event.is_writable() {
                    return Ok(());
                }

                let state_data = state.borrow_mut();

                if self.upstream_writer.is_empty() {
                    let mut client_response = ClientResponseEncrypted::new();
                    client_response.clone_from(&state_data.downstream_client_response_encrypted);
                    client_response.fingerprint_response.clear();

                    if let Some(fingerprint_challenge) =
                        state_data.upstream_ap_response.challenge.fingerprint_challenge.as_ref()
                    {
                        if let Some(grain_challenge) = fingerprint_challenge.grain.as_ref() {
                            // Get SHA1 of accumulator
                            let accumulator_hash = sha1_digest(&state_data.upstream_accumulator);

                            // Encrypt hash
                            let kek = grain_challenge.kek();
                            let mut hash_encryptor = Grain128::keysetup(kek, 128, 128);
                            hash_encryptor.ivsetup(&[0; 16]);
                            let mut encrypted_hash = [0; 16];
                            hash_encryptor.encrypt_bytes(&accumulator_hash[0..16], &mut encrypted_hash);

                            // Encrypt the grain key using encrypted accumulator hash
                            let encrypted_key =
                                Aes128CbcEncrypt::new(&encrypted_hash.into(), &[0; 16].into())
                                    .encrypt_padded_vec_mut::<block_padding::NoPadding>(&self.upstream_grain_key);

                            client_response
                                .fingerprint_response
                                .mut_or_insert_default()
                                .grain
                                .mut_or_insert_default()
                                .set_encrypted_key(encrypted_key);
                            trace!(
                                "[{}] Sent upstream grain key: {}",
                                self.downstream_addr,
                                hex::encode(&self.upstream_grain_key)
                            );
                        }
                        if let Some(_hmac_ripemd_challenge) = fingerprint_challenge.hmac_ripemd.as_ref() {
                            unimplemented!("HMAC RipeMD is unknown, please open an issue on Github");
                        }
                    }

                    let Some(upstream_cipher) = self.upstream_cipher.as_mut() else {
                        return Err(Error::other("No upstream cipher while trying to send ClientResponseEncrypted"));
                    };
                    let mut packet = vec![];
                    packet.push(LOGIN_PACKET);
                    let client_response_len = client_response.compute_size() as u16;
                    let client_response_len_bytes = client_response_len.to_be_bytes();
                    packet.extend_from_slice(&client_response_len_bytes);
                    packet.append(&mut client_response.write_to_bytes()?);
                    self.pcap_writer.borrow_mut().write_packet(
                        self.upstream_iface.unwrap(),
                        PacketDirection::Send,
                        Cow::Borrowed(&packet),
                    );
                    trace!(
                        "[{}] Sending {} bytes for ClientResponseEncrypted {}",
                        self.downstream_addr,
                        packet.len() + 4,
                        hex::encode(&packet)
                    );
                    upstream_cipher.encrypt(&mut packet);
                    self.upstream_writer = NonblockingWriter::new(packet);
                }

                match self.upstream_writer.write(&mut self.upstream) {
                    Ok(bytes_written) => {
                        trace!("[{}] Written {bytes_written} bytes of ClientResponseEncrypted", self.downstream_addr,);
                    },
                    Err(error) => return Err(error),
                }

                if !self.upstream_writer.is_complete() {
                    return Ok(());
                }

                let _ = self.upstream_writer.take();
                drop(state_data);
                self.state = ProxySessionState::Idle;
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);

                Ok(())
            },
            ProxySessionState::Idle => {
                if *token == self.downstream_token {
                    if !event.is_readable() {
                        return Ok(());
                    }
                    let mut header = [0; 3];
                    if self.downstream.read_exact(&mut header).is_err() {
                        return Ok(());
                    }
                    let downstream_cipher = self.downstream_cipher.as_mut().unwrap();
                    let DecryptResult::Header(packet_type, packet_len) = downstream_cipher.decrypt(&header) else {
                        #[cfg(debug_assertions)]
                        panic!("Decryption mismatch, expected header got body");
                        #[cfg(not(debug_assertions))]
                        return Err(Error::new(ErrorKind::Other, "Decryption mismatch, expected header got body"));
                    };
                    self.downstream_decrypt_packet_type = packet_type;
                    self.downstream_decrypt_packet_len = packet_len;
                    self.downstream_reader = NonblockingReader::new(packet_len as usize + 4);
                    self.state = ProxySessionState::ReadDownstream;
                    trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                    Ok(())
                } else if *token == self.upstream_token {
                    if !event.is_readable() {
                        return Ok(());
                    }
                    let mut header = [0; 3];
                    if self.upstream.read_exact(&mut header).is_err() {
                        return Ok(());
                    }
                    let upstream_cipher = self.upstream_cipher.as_mut().unwrap();
                    let DecryptResult::Header(packet_type, packet_len) = upstream_cipher.decrypt(&header) else {
                        #[cfg(debug_assertions)]
                        panic!("Decryption mismatch, expected header got body");
                        #[cfg(not(debug_assertions))]
                        return Err(Error::new(ErrorKind::Other, "Decryption mismatch, expected header got body"));
                    };
                    self.upstream_decrypt_packet_type = packet_type;
                    self.upstream_decrypt_packet_len = packet_len;
                    self.upstream_reader = NonblockingReader::new(packet_len as usize + 4);
                    self.state = ProxySessionState::ReadUpstream;
                    trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                    Ok(())
                } else {
                    panic!("Token {token:?} doesn't belong to us {self}");
                }
            },
            ProxySessionState::ReadDownstream => {
                if *token != self.downstream_token || !event.is_readable() {
                    return Ok(());
                }

                match self.downstream_reader.read(&mut self.downstream) {
                    Ok(bytes_read) => {
                        trace!("[{}] Read {bytes_read} bytes from downstream", self.downstream_addr);
                    },
                    Err(error) => return Err(error),
                }

                if !self.downstream_reader.is_complete() {
                    return Ok(());
                }

                let downstream_cipher = self.downstream_cipher.as_mut().unwrap();
                let DecryptResult::Body(mut decrypted_packet) =
                    downstream_cipher.decrypt(&self.downstream_reader.take())
                else {
                    #[cfg(debug_assertions)]
                    panic!("Decryption mismatch, expected body got header");
                    #[cfg(not(debug_assertions))]
                    return Err(Error::new(ErrorKind::Other, "Decryption mismatch, expected body got header"));
                };
                let mut encrypted_packet = Vec::new();
                encrypted_packet.push(self.downstream_decrypt_packet_type);
                encrypted_packet.extend_from_slice(&self.downstream_decrypt_packet_len.to_be_bytes());
                encrypted_packet.append(&mut decrypted_packet);
                self.pcap_writer.borrow_mut().write_packet(
                    self.downstream_iface.unwrap(),
                    PacketDirection::Recv,
                    Cow::Borrowed(&encrypted_packet),
                );
                self.pcap_writer.borrow_mut().write_packet(
                    self.upstream_iface.unwrap(),
                    PacketDirection::Send,
                    Cow::Borrowed(&encrypted_packet),
                );
                let upstream_cipher = self.upstream_cipher.as_mut().unwrap();
                upstream_cipher.encrypt(&mut encrypted_packet);
                self.upstream_writer = NonblockingWriter::new(encrypted_packet);
                self.state = ProxySessionState::SendUpstream;
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                Ok(())
            },
            ProxySessionState::SendUpstream => {
                if *token != self.upstream_token || !event.is_writable() {
                    return Ok(());
                }

                match self.upstream_writer.write(&mut self.upstream) {
                    Ok(bytes_written) => {
                        trace!("[{}] Wrote {bytes_written} bytes to upstream", self.downstream_addr);
                    },
                    Err(error) => return Err(error),
                }

                if !self.upstream_writer.is_complete() {
                    return Ok(());
                }

                let _ = self.upstream_writer.take();
                self.state = ProxySessionState::Idle;
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);

                Ok(())
            },
            ProxySessionState::ReadUpstream => {
                if *token != self.upstream_token || !event.is_readable() {
                    return Ok(());
                }

                match self.upstream_reader.read(&mut self.upstream) {
                    Ok(bytes_read) => {
                        trace!("[{}] Read {bytes_read} bytes from upstream", self.downstream_addr);
                    },
                    Err(error) => return Err(error),
                }

                if !self.upstream_reader.is_complete() {
                    return Ok(());
                }

                let upstream_cipher = self.upstream_cipher.as_mut().unwrap();
                let DecryptResult::Body(mut decrypted_packet) = upstream_cipher.decrypt(&self.upstream_reader.take())
                else {
                    #[cfg(debug_assertions)]
                    panic!("Decryption mismatch, expected body got header");
                    #[cfg(not(debug_assertions))]
                    return Err(Error::new(ErrorKind::Other, "Decryption mismatch, expected body got header"));
                };
                let mut encrypted_packet = Vec::new();
                encrypted_packet.push(self.upstream_decrypt_packet_type);
                encrypted_packet.extend_from_slice(&self.upstream_decrypt_packet_len.to_be_bytes());
                encrypted_packet.append(&mut decrypted_packet);
                self.pcap_writer.borrow_mut().write_packet(
                    self.upstream_iface.unwrap(),
                    PacketDirection::Recv,
                    Cow::Borrowed(&encrypted_packet),
                );
                self.pcap_writer.borrow_mut().write_packet(
                    self.downstream_iface.unwrap(),
                    PacketDirection::Send,
                    Cow::Borrowed(&encrypted_packet),
                );
                let downstream_cipher = self.downstream_cipher.as_mut().unwrap();
                downstream_cipher.encrypt(&mut encrypted_packet);
                self.upstream_decrypt_packet_len = 0;
                self.upstream_decrypt_packet_type = 0;
                self.downstream_writer = NonblockingWriter::new(encrypted_packet);
                self.state = ProxySessionState::SendDownstream;
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);
                Ok(())
            },
            ProxySessionState::SendDownstream => {
                if *token != self.downstream_token || !event.is_writable() {
                    return Ok(());
                }

                match self.downstream_writer.write(&mut self.downstream) {
                    Ok(bytes_written) => {
                        trace!("[{}] Wrote {bytes_written} bytes to downstream", self.downstream_addr);
                    },
                    Err(error) => return Err(error),
                }

                if !self.downstream_writer.is_complete() {
                    return Ok(());
                }

                let _ = self.downstream_writer.take();
                self.state = ProxySessionState::Idle;
                trace!("[{}] Updated state to {}", self.downstream_addr, self.state);

                Ok(())
            },
            ProxySessionState::Complete => {
                #[cfg(debug_assertions)]
                panic!("Complete handler should never run");
                #[cfg(not(debug_assertions))]
                Ok(())
            },
        }
    }

    pub fn register_sockets(&mut self, registry: &Registry) -> Result<(), Error> {
        registry.register(&mut self.downstream, self.downstream_token, Interest::READABLE)?;
        registry.register(&mut self.upstream, self.upstream_token, Interest::WRITABLE)?;
        Ok(())
    }

    pub fn reregister_sockets(&mut self, registry: &Registry) -> Result<(), Error> {
        match self.state {
            ProxySessionState::ReadDownstreamClientHello(_) => {
                registry.reregister(&mut self.downstream, self.downstream_token, Interest::READABLE)?;
            },
            ProxySessionState::ConnectingToUpstream(_) => {
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::WRITABLE)?;
            },
            ProxySessionState::SendUpstreamClientHello(_) => {
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::WRITABLE)?;
            },
            ProxySessionState::ReadUpstreamAPChallenge(_) => {
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::READABLE)?;
            },
            ProxySessionState::SendDownstreamAPChallenge(_) => {
                registry.reregister(&mut self.downstream, self.downstream_token, Interest::WRITABLE)?;
            },
            ProxySessionState::ReadDownstreamClientResponsePlaintext(_) |
            ProxySessionState::ReadDownstreamClientResponseEncrypted(_) => {
                registry.reregister(&mut self.downstream, self.downstream_token, Interest::READABLE)?;
            },
            ProxySessionState::SendUpstreamClientResponsePlaintext(_) |
            ProxySessionState::SendUpstreamClientResponseEncrypted(_) => {
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::WRITABLE)?;
            },
            ProxySessionState::Idle => {
                registry.reregister(&mut self.downstream, self.downstream_token, Interest::READABLE)?;
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::READABLE)?;
            },
            ProxySessionState::ReadDownstream => {
                registry.reregister(&mut self.downstream, self.downstream_token, Interest::READABLE)?;
            },
            ProxySessionState::SendUpstream => {
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::WRITABLE)?;
            },
            ProxySessionState::ReadUpstream => {
                registry.reregister(&mut self.upstream, self.upstream_token, Interest::READABLE)?;
            },
            ProxySessionState::SendDownstream => {
                registry.reregister(&mut self.downstream, self.downstream_token, Interest::WRITABLE)?;
            },
            ProxySessionState::Complete => {},
        }
        Ok(())
    }

    pub fn deregister_sockets(&mut self, registry: &Registry) -> Result<(), Error> {
        registry.deregister(&mut self.downstream)?;
        registry.deregister(&mut self.upstream)?;
        Ok(())
    }

    pub fn timeout_advice(&self) -> ProxyTimeoutAdvice {
        match self.state {
            ProxySessionState::ReadDownstreamClientHello(ref state) |
            ProxySessionState::ConnectingToUpstream(ref state) => {
                if state.borrow().upstream_timeout < Instant::now() {
                    ProxyTimeoutAdvice::TimedOut
                } else {
                    ProxyTimeoutAdvice::KeepWaiting
                }
            },
            _ => ProxyTimeoutAdvice::StopChecking,
        }
    }
}
