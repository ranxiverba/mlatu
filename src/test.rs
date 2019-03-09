use generic_array::GenericArray;
use secp256k1::{PublicKey, SecretKey};
use super::Processed;

mod packet {
    use super::super::{PseudoRandomStream, Packet};
    use sha2::Sha256;
    use chacha::ChaCha;
    use hmac::Hmac;
    use secp256k1::SecretKey;
    use digest::{Input, BlockInput, FixedOutput, Reset};
    use generic_array::{GenericArray, typenum::{U16, U32}};

    pub type FullPacket<L, N, P> = Packet<(SecretKey, Hmac<Sha256>, Sha256, ChaCha), L, N, P>;
    pub type TruncatedPacket<L, N, P> =
        Packet<(SecretKey, Hmac<TruncatedSha256>, Sha256, ChaCha), L, N, P>;

    impl PseudoRandomStream<U16> for ChaCha {
        fn seed(v: GenericArray<u8, U16>) -> Self {
            let mut array = [0; 32];
            array[0..16].copy_from_slice(v.as_ref());
            array[16..].copy_from_slice(v.as_ref());
            ChaCha::new_chacha20(&array, &[0u8; 8])
        }
    }

    impl PseudoRandomStream<U32> for ChaCha {
        fn seed(v: GenericArray<u8, U32>) -> Self {
            let mut array = [0; 32];
            array.copy_from_slice(v.as_ref());
            ChaCha::new_chacha20(&array, &[0u8; 8])
        }
    }

    pub struct TruncatedSha256(Sha256);

    impl Input for TruncatedSha256 {
        fn input<B: AsRef<[u8]>>(&mut self, data: B) {
            self.0.input(data)
        }
    }

    impl BlockInput for TruncatedSha256 {
        type BlockSize = <Sha256 as BlockInput>::BlockSize;
    }

    impl FixedOutput for TruncatedSha256 {
        type OutputSize = U16;

        fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
            use generic_array::sequence::GenericSequence;

            let o = self.0.fixed_result();
            GenericArray::generate(|x| o[x])
        }
    }

    impl Reset for TruncatedSha256 {
        fn reset(&mut self) {
            self.0.reset()
        }
    }

    impl Default for TruncatedSha256 {
        fn default() -> Self {
            TruncatedSha256(Sha256::default())
        }
    }

    impl Clone for TruncatedSha256 {
        fn clone(&self) -> Self {
            TruncatedSha256(self.0.clone())
        }
    }
}

use self::packet::{FullPacket, TruncatedPacket};

#[test]
fn packet() {
    use generic_array::typenum::{U33, U20};
    use serde_derive::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize)]
    struct Empty;

    impl AsMut<[u8]> for Empty {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut []
        }
    }

    let reference_packet = "02eec7245d6b7d2ccb30380bfbe2a3648cd7\
                            a942653f5aa340edcea1f283686619e5f14350c2a76fc232b5e4\
                            6d421e9615471ab9e0bc887beff8c95fdb878f7b3a71da571226\
                            458c510bbadd1276f045c21c520a07d35da256ef75b436796243\
                            7b0dd10f7d61ab590531cf08000178a333a347f8b4072e216400\
                            406bdf3bf038659793a86cae5f52d32f3438527b47a1cfc54285\
                            a8afec3a4c9f3323db0c946f5d4cb2ce721caad69320c3a469a2\
                            02f3e468c67eaf7a7cda226d0fd32f7b48084dca885d15222e60\
                            826d5d971f64172d98e0760154400958f00e86697aa1aa9d41be\
                            e8119a1ec866abe044a9ad635778ba61fc0776dc832b39451bd5\
                            d35072d2269cf9b040d6ba38b54ec35f81d7fc67678c3be47274\
                            f3c4cc472aff005c3469eb3bc140769ed4c7f0218ff8c6c7dd72\
                            21d189c65b3b9aaa71a01484b122846c7c7b57e02e679ea8469b\
                            70e14fe4f70fee4d87b910cf144be6fe48eef24da475c0b0bcc6\
                            565ae82cd3f4e3b24c76eaa5616c6111343306ab35c1fe5ca4a7\
                            7c0e314ed7dba39d6f1e0de791719c241a939cc493bea2bae1c1\
                            e932679ea94d29084278513c77b899cc98059d06a27d171b0dbd\
                            f6bee13ddc4fc17a0c4d2827d488436b57baa167544138ca2e64\
                            a11b43ac8a06cd0c2fba2d4d900ed2d9205305e2d7383cc98dac\
                            b078133de5f6fb6bed2ef26ba92cea28aafc3b9948dd9ae5559e\
                            8bd6920b8cea462aa445ca6a95e0e7ba52961b181c79e73bd581\
                            821df2b10173727a810c92b83b5ba4a0403eb710d2ca10689a35\
                            bec6c3a708e9e92f7d78ff3c5d9989574b00c6736f84c199256e\
                            76e19e78f0c98a9d580b4a658c84fc8f2096c2fbea8f5f8c59d0\
                            fdacb3be2802ef802abbecb3aba4acaac69a0e965abd8981e989\
                            6b1f6ef9d60f7a164b371af869fd0e48073742825e9434fc54da\
                            837e120266d53302954843538ea7c6c3dbfb4ff3b2fdbe244437\
                            f2a153ccf7bdb4c92aa08102d4f3cff2ae5ef86fab4653595e6a\
                            5837fa2f3e29f27a9cde5966843fb847a4a61f1e76c281fe8bb2\
                            b0a181d096100db5a1a5ce7a910238251a43ca556712eaadea16\
                            7fb4d7d75825e440f3ecd782036d7574df8bceacb397abefc5f5\
                            254d2722215c53ff54af8299aaaad642c6d72a14d27882d9bbd5\
                            39e1cc7a527526ba89b8c037ad09120e98ab042d3e8652b31ae0\
                            e478516bfaf88efca9f3676ffe99d2819dcaeb7610a626695f53\
                            117665d267d3f7abebd6bbd6733f645c72c389f03855bdf1e4b8\
                            075b516569b118233a0f0971d24b83113c0b096f5216a207ca99\
                            a7cddc81c130923fe3d91e7508c9ac5f2e914ff5dccab9e55856\
                            6fa14efb34ac98d878580814b94b73acbfde9072f30b881f7f0f\
                            ff42d4045d1ace6322d86a97d164aa84d93a60498065cc7c20e6\
                            36f5862dc81531a88c60305a2e59a985be327a6902e4bed986db\
                            f4a0b50c217af0ea7fdf9ab37f9ea1a1aaa72f54cf40154ea9b2\
                            69f1a7c09f9f43245109431a175d50e2db0132337baa0ef97eed\
                            0fcf20489da36b79a1172faccc2f7ded7c60e00694282d93359c\
                            4682135642bc81f433574aa8ef0c97b4ade7ca372c5ffc23c7ed\
                            dd839bab4e0f14d6df15c9dbeab176bec8b5701cf054eb3072f6\
                            dadc98f88819042bf10c407516ee58bce33fbe3b3d86a54255e5\
                            77db4598e30a135361528c101683a5fcde7e8ba53f3456254be8\
                            f45fe3a56120ae96ea3773631fcb3873aa3abd91bcff00bd38bd\
                            43697a2e789e00da6077482e7b1b1a677b5afae4c54e6cbdf737\
                            7b694eb7d7a5b913476a5be923322d3de06060fd5e819635232a\
                            2cf4f0731da13b8546d1d6d4f8d75b9fce6c2341a71b0ea6f780\
                            df54bfdb0dd5cd9855179f602f917265f21f9190c70217774a6f\
                            baaa7d63ad64199f4664813b955cff954949076dcf";
    let secret_key_text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let associated_data_text = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let public_keys_texts = [
        "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
    ];

    let secret_key = SecretKey::from_slice(secret_key_text.as_bytes()).unwrap();
    let associated_data = associated_data_text.as_bytes().to_vec();
    let path = public_keys_texts.iter().enumerate().map(|(i, &d)| {
        let pk = PublicKey::from_slice(hex::decode(d).unwrap().as_slice()).unwrap();
        let x = i as u8;
        let payload = GenericArray::clone_from_slice(&[
            0, x, x, x, x, x, x, x, x, 0, 0, 0, 0, 0, 0, 0, x, 0, 0, 0, x, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        (pk, payload)
    });

    let packet =
        FullPacket::<U33, U20, Empty>::new(associated_data, secret_key, path, Empty).unwrap();

    use tirse::{DefaultBinarySerializer, WriteWrapper};
    use serde::Serialize;

    let s = DefaultBinarySerializer::<WriteWrapper<Vec<_>>, String>::new(Vec::new());
    let v = packet.serialize(s).unwrap().consume().into_inner();

    assert_eq!(hex::encode(v), reference_packet);
}

#[test]
#[allow(non_shorthand_field_patterns)]
fn path() {
    use generic_array::typenum::{U19, U5};
    use generic_array::sequence::GenericSequence;
    use secp256k1::Secp256k1;
    use either::{Left, Right};
    use std::fmt;
    use serde::{Serialize, Serializer};
    use tirse::{DefaultBinarySerializer, WriteWrapper};

    const MESSAGE_LENGTH: usize = 4096 - 224;

    #[derive(Clone)]
    struct Message([u8; MESSAGE_LENGTH]);

    impl Message {
        pub fn random() -> Self {
            let mut array = [0; MESSAGE_LENGTH];
            for i in 0..MESSAGE_LENGTH {
                array[i] = rand::random();
            }
            Message(array)
        }
    }

    impl Eq for Message {}

    impl PartialEq<Self> for Message {
        fn eq(&self, other: &Self) -> bool {
            (0..MESSAGE_LENGTH).fold(true, |a, index| a && self.0[index] == other.0[index])
        }
    }

    impl fmt::Debug for Message {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", hex::encode(self))
        }
    }

    impl AsRef<[u8]> for Message {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }

    impl AsMut<[u8]> for Message {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0[..]
        }
    }

    impl Serialize for Message {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(MESSAGE_LENGTH)?;
            for i in 0..MESSAGE_LENGTH {
                tuple.serialize_element(&self.0[i])?;
            }
            tuple.end()
        }
    }

    let context = Secp256k1::new();

    let (secrets, route): (Vec<SecretKey>, Vec<(PublicKey, _)>) = (0..4)
        .map(|_| {
            let secret = SecretKey::new(&mut rand::thread_rng());
            let public = PublicKey::from_secret_key(&context, &secret);
            let payload = GenericArray::<u8, _>::generate(|_| rand::random());
            (secret, (public, payload))
        })
        .unzip();

    let payloads = route
        .iter()
        .map(|(_, payload)| {
            dbg!(hex::encode(&payload));
            payload.clone()
        })
        .collect::<Vec<_>>();

    let message = Message::random();
    let packet = TruncatedPacket::<U19, U5, Message>::new(
        &[],
        SecretKey::new(&mut rand::thread_rng()),
        route.into_iter(),
        message.clone(),
    )
    .unwrap();

    let s = DefaultBinarySerializer::<WriteWrapper<Vec<_>>, String>::new(Vec::new());
    let v = packet.serialize(s).unwrap().consume().into_inner();

    let initial = (Left(packet), Vec::new());
    let (last, output) = secrets
        .into_iter()
        .fold(initial, |(packet, mut payloads), secret| {
            match packet.left().unwrap().process(&[], secret).unwrap() {
                Processed::Forward {
                    data: data,
                    next: next,
                } => {
                    dbg!(hex::encode(&data));
                    payloads.push(data);
                    (Left(next), payloads)
                },
                Processed::Exit {
                    data: data,
                    message: message,
                } => {
                    dbg!(hex::encode(&data));
                    dbg!(hex::encode(message.as_ref()));
                    payloads.push(data);
                    (Right(message), payloads)
                },
            }
        });

    dbg!(hex::encode(&v));
    assert_eq!(payloads, output);
    assert_eq!(last.right(), Some(message));
    assert_eq!(v.len(), 4096);
}
