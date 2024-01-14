// Research done by matching symbols from version 0.7.2.26 for iOS with latest linux version (122501009)
// Frida used for hooking and logging
//
// _ZN2sp12hashcash_keyE (sp::hashcash_key)
// A3 AD B1 31 AB 58 45 07 CB 7A 68 AE E1 A5 F9 0B 4D 7F 07 11
//
// Pseudocode looks like this:
//  `suffix` is a pointer to the mutable protobuf array (output)
//  `prefix` and `prefix_len` come from the AP challenge
//  `length` comes from the AP challenge, specifies how many trailing zero bits are needed
//  `target` is XOR'd with the suffix before checking the trailing zeroes
// ApConnectionImpl::powSolveHashcash(this, suffix, prefix, prefix_len, length, target)
//   sha_hmac_ctx = SHA1HMAC::new(sp::hashcash_key, 20);
//   sha_hmac_ctx.update(this->client_hello); // Includes SPIRC_MAGIC 0004
//   sha_hmac_ctx.update(this->ap_response);
//   context_bytes = sha_hmac_ctx.finish();
//   context = BigEndian::read64(context_bytes);
//
//   memset(suffix, 0, 16);
//   for (i = 0; ; i++, context++) {
//     BigEndian::write64(&suffix[0x0], context);
//     BigEndian::write64(&suffix[0x8], i);
//     sha_ctx = SHA1::new()
//     sha_ctx.update(prefix, prefix_len);
//     sha_ctx.update(suffix, 16);
//     digest = sha_ctx.finish();
//
//     if ( ( (BigEndian::read32(&digest[16]) ^ target) & (1 << length) -1) == 0 ) {
//       break;
//     }
//   }
// }
//
// The if condition is an optimised way to check the number of zero bits at the end of the digest after XOR'ing with `target`
// It works by interpreting the last 4 bytes of the digest as a big-endian int then AND with a bitmask created using the length
// e.g. if the length is 2, 1<<2=4, 4-1=3=0b11, if n & 0b11 == 0, then last 2 bits are zero
// Without access it can only be assumed that the challenges are generated randomly, and adjusting the length allows for a kind
// of DDoS protection/ratelimit. If anyone knows a mathematical way to generate challenges feel free to open a PR
//
// In newer versions the function is no longer a member method, new signature:
// int powSolveHashcash(base::Array client_hello, base::Array ap_response, unsigned char *prefixPtr, unsigned int prefixLen, unsigned int length, unsigned int target);
// base::Array stores a pointer to the start and end of an array:
//   00000000 base::Array     struc ; (sizeof=0x10)
//   00000000 startPtr        dq ?                    ; void*
//   00000008 endPtr          dq ?                    ; void*
//   00000010 base::Array     ends

use std::io::{Error, ErrorKind};

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use pineapple_proto::keyexchange_old::PoWHashCashChallenge;
use sha1::{Digest, Sha1};

type HmacSha1 = Hmac<Sha1>;

lazy_static! {
    static ref HASHCASH_KEY: Vec<u8> = vec![
        0xA3, 0xAD, 0xB1, 0x31, 0xAB, 0x58, 0x45, 0x07, 0xCB, 0x7A, 0x68, 0xAE, 0xE1, 0xA5, 0xF9, 0x0B, 0x4D, 0x7F,
        0x07, 0x11,
    ];
}

pub fn solve_hashcash(accumulator: &[u8], challenge: &PoWHashCashChallenge) -> Result<Vec<u8>, Error> {
    let mut hmac_ctx = HmacSha1::new_from_slice(&HASHCASH_KEY)
        .map_err(|_| Error::new(ErrorKind::Other, "Failed to create HMAC instance"))?;
    hmac_ctx.update(accumulator);
    let context_bytes = hmac_ctx.finalize().into_bytes();
    let mut context = BigEndian::read_u64(&context_bytes);

    let prefix = challenge.prefix();
    let length = challenge.length() as u32;
    let target = challenge.target() as u32;
    let mut suffix = vec![0; 16];

    let mut idx = 0;
    loop {
        BigEndian::write_u64(&mut suffix[0x0..0x08], context);
        BigEndian::write_u64(&mut suffix[0x8..0x10], idx);
        let mut sha_ctx = Sha1::new();
        sha_ctx.update(prefix);
        sha_ctx.update(&suffix);
        let digest = sha_ctx.finalize();

        if (BigEndian::read_u32(&digest[16..]) ^ target).trailing_zeros() >= length {
            break;
        }

        idx += 1;
        context += 1;
    }

    Ok(suffix)
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use pineapple_proto::keyexchange_old::APResponseMessage;
    use protobuf::Message;

    use super::solve_hashcash;

    struct TestData {
        client_hello: Vec<u8>,
        ap_response: Vec<u8>,
        suffix: Vec<u8>,
    }

    lazy_static! {
        static ref TEST_DATA: Vec<TestData> = vec![
            TestData {
                client_hello: hex::decode("000400000167520e5000a00100f00108c00291efb43aa00100f00100c0020092036752655260870b857ed1a36d08564fec32f52467b56a870a9b5f8b4b640bc336af1b67391d76c48b0b24f2dd6414285cb21589a5067c6df8b25b9bd7a26fa34f6522833ad12a15f8efd92ff039b5116e0a6761992f6bb69cf2507587eb0983b22af911214aa00101e2031079d166762568669d533bac38de661e44b204bc01a83d8f6b80e8bf505cb76485cab8cef26c0add9b03cf4fa86c6c302d27383dd06eb4ff22daa8b7a52c77cedd3ef23f0579b4cb1b4d7d414803746a0a2f7e60571a090bc4dff3048e5e5ca1fa9c153c0e3d66ba632d5ee894f28e0e109e7f4cee277b9d53071547e5e08100db90d859dca7ff2f4e9c9108a566b1bc512bd5636a9c031f6eb84f1ba486b17d5e96f92f607a688d10cf0b0f44cc78298b7b45dbf6082482489e5f57db1c0be001b8b30e6ea13566db8657b035a1838ced82050808011a002a020800").unwrap(),
                ap_response: hex::decode("0000027152ea0452ec0252e90252601a69efa73d4feff45aeb979eb40e564c0a4de78ccf094756f6a718466956c57a0d171abd53597a33cfc707745b013fccfa61007033abb211812577f43fa929a15b9c4c12f734dc0ca081c2a3749011dccf814e632118298aaf22adc682d182b0a00100f20180029033df6737197552d5138fc3a43ec5b665e8be2727164b8f20b80e6bb1455228c6b033651b0346c50e90941aaaac79869ec5448d40da1f73f1d7bb0868dd6328073c8139ebb1a46bdb5dd0dde31d5ef4ccad6c25127121d5d9beec4578ff3b0766a04fa6d852b919bd76b39fbdff6f359a0994ceb4850582b356d0954704c2ba695286d2ecf3c1cd0ef0294e337878aac2b0d5e901f5fb23ad57ba0471bdcfcdf109935cb8b747416a40a83faa40cc333afee2bce1eb97d5a8fabcb4b030b171e660eefe6d71d3a29f09057daf04b5b2caac2a8ae174b1c71bf75ae4740d777c134e7abe23fcf5e5f2ba3b8e189c842c0aa760cceb8bc868c877391f687dc4cda2011452125210abefe861ef68aae037a18011974d275af2011c521a5210cd16c3e83857847f4ecc7053827e813fa0010ff001c5d701c202025200920310cd16c3e83857847f4ecc7053827e813fe203a9015fb1b9de00854e5308cdd5479240f28228537190fd51c79ed2d9361f00905560420e3e42948d959c5a6ae3ecaad56ed328df6325312bc30304f922048a7764cc86a30e1a30a3b68a0e9976b86ee58b96c4efbbf51a7ef81e781b22029287ce182adc325a7fe8e48d815a46ef3fd18504c040f9dabff2f8370d1b399fa207b8cce3ea2662d30af054643644a407c9a8c80aa1a2c9939b00a0b639405840f82423e24a85b554750ab8ab").unwrap(),
                suffix: hex::decode("ed569bf4bb14e940000000000000402e").unwrap()
            },
            TestData {
                client_hello: hex::decode("00040000010c520f5002a00100f00106c002ecf298a803a00100f00100c0020092036752655260b3fd37830a4d0bbbd6c3e525dff21893519459b4a2b7d1906f534be83d3a9b30366db90ca7b905ee5cbc9a007f83147d64063f8370a8d079dff5104ce239e39b08eb7e4afc24af4e47e9638a76738b784210720ea50fdc479bfda61daf68c2e7a00101e203100a44c7d6acc2284e7db6cd6291203b32b204618cd2a3869be9c19ad39920327f8cecdf808c6f51ded6c27193393c663b9f238209dd1019ace7f4264f817e8ebee3b50cf54c215395d2253394445f4ec6fe0d8cdf9ebcbe07ab215db9338eb93b8c47498199a54dec4e3e3aac866e36826a9df16e82050808011a002a020800").unwrap(),
                ap_response: hex::decode("000001b552ae0352ec0252e90252608067917e7fcc9b712626f9c40c6e36b026fcd9a655af738939ae13826f3740c8162e217db6a7aeeb35df1e9435a3173b51e587e252ae8b38325f029a611deaf24d5b68c1e4b03ead039a0fa90856163e841003a57586b16c77b4134b4a36c6cfa00100f20180022e13f61001f1c695c006045ca51a0197f240914f45ea4abe7615da83ad8201f9e5a1652351255ba18383e77313bfe451b8e12b2af47b1781201c9c9f32f150802c528434704507d4883de3d286eb8575bd7c034a9bbd672f181f6e5f32590bae3c1e308bb10d4d1831fe529fd81f2e0432a6fd95db8dd0c14f5e6cf91a759e27f9c6bdeb54b04d490946d1c198708924769a0dd1d8694c5f70b182e4f415176c9d460db50263064d8bac10202763eca22f9844031263be5bf3a17a59022edc58f4e0039d662053a5f0286ffcbfdf81abaa77a13cb03e5e275cba7797a9f615c1043bb01b95e1fd8a2350092cd9c86aece409c5d9eff901d9a922b39c3bf18bdea20100f2011c521a5210012343e964aa0a809947db23803da79aa0010ff00195fb01c2020252009203107e05cb232fcb98d65e8c8672d05faefce203027ed1").unwrap(),
                suffix: hex::decode("1a70506a514371730000000000000c05").unwrap()
            },
            // Length 22, can take upwards of 20 seconds on debug builds
            // TestData {
            //     client_hello: hex::decode("0004000000bd520f5002a00100f00106c002ecf298a803a00100f00100c0020092036752655260c6471cabd765e50382b4d0ea8bb4af9643bcc6dd04c8746169eb8d650c68298be304fa5c5a04c65530bdcc27ccfa33406ee7e41af0f9d4a327b29d4b048b8d790f376e62760af63da77c562fd150d83662162b9acdfccd955739494540ed439ca00101e20310b4c2a062105ddfdd82899863b6ec7dd3b204127c0ea614716dfd81ad6a393505a9829563cb82050808011a002a020800").unwrap(),
            //     ap_response: hex::decode("000001c952c20352ec0252e902526089955fd3f82384177977d99377eb08946d28c242ea59db06cb8d30b41268b36839b1e90e307626c2a94d73cf0600d03d154dc9dbf160f029d6d25e81858db30c25227f6a2fab8b7ec173f469417e5b23d1f9a91b90bcc724801b77e9be93314ea00100f201800275bad753620cb62d924f58cc1b1ba3dc2441c4599f60adaf8da179e3bed3140356b42ca50fc0416ecadaf599e094a58b09ac3be5222fcc7515bb024e11ffccb2a2e113a85c5e5a124dbd13a4317996bbe004974bdbc1312677d419421bcabeb6bac35800cf7a0f2b3e0fb30ef5021a2bdb0f47c859b74d880b063f44ed7bd717ae0e1178ca0c5fb16c8f4dca5d34a2c5fd8b076c2501dc483da3c0930feab8fa7ba6daba8eecd865ce3f6a5262734a9d6de859cc576b81782bc45fb5723f072bbdcadd6f0c0eb6397565b22d968408753f78d3b567e235435b3ec7d0efdfbdb72d7cb85db043fe97f872584d99430362ba06283ecb747a9e136167d75fabe1f4a2011452125210856323c6e4a5ec5e1a5b44b7d0d977fbf2011c521a521021eaa61cbd0282e83b54e3557ce40bf7a00116f001c3f201c202025200920310492252ea5501a33c12f66fbf928a5135e203020638").unwrap(),
            //     suffix: hex::decode("e8452484e80592c60000000000633e97").unwrap()
            // }
        ];
    }

    #[test]
    fn test_hashcash() {
        for test_data in TEST_DATA.iter() {
            assert_eq!(test_data.client_hello[0..2], [0x00, 0x04]);
            let client_hello_length = u32::from_be_bytes(test_data.client_hello[2..6].try_into().unwrap());
            assert_eq!(client_hello_length as usize, test_data.client_hello.len());
            let ap_response_length = u32::from_be_bytes(test_data.ap_response[0..4].try_into().unwrap());
            assert_eq!(ap_response_length as usize, test_data.ap_response.len());

            let ap_response_msg =
                APResponseMessage::parse_from_bytes(&test_data.ap_response[4..]).expect("Failed to parse APResponse");
            let hashcash_challenge =
                ap_response_msg.challenge.pow_challenge.hash_cash.as_ref().expect("Expected POW challenge");
            let mut accumulator = vec![];
            accumulator.extend_from_slice(&test_data.client_hello);
            accumulator.extend_from_slice(&test_data.ap_response);

            assert_eq!(
                test_data.suffix,
                solve_hashcash(&accumulator, hashcash_challenge).expect("Failed to solve challenge")
            )
        }
    }
}
