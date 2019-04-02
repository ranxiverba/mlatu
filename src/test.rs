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

    let reference_packet = "\
                            02e90777e8702e3d587e17c8627a997b0225f4a5a5f82115f13046aab95513c6d6\
                            3180bc084cc0f52d4ebcc8a69607518b8e0e24dc54b2fb1833d45fa8b5395a7ebc\
                            3263114916dafe806741f9b178476afdeff3628cba5126d9cb2627bb11e4e50b\
                            3cdae95e3b343e054f69ab45024db67c78521dc20d91ce995d4650c7c93a99d2cb\
                            60302b35ca6ec0e5f1f5c6b595d9ce327c5c28fc6d5859830bff356d9ffbacc2\
                            6d9703e203dc5cf023340d206c53dc9b082667d56970b14abae8b079e5d3d7a412\
                            0e4e5bb6833c04254924297561a4554a11ff46b93293285026b5045d0689bda6\
                            34a47b64969f2f2aaa9e4c85f3d1d8365f6d49a4963b341ab8e7e56f0f8ce53d33\
                            21eddf20f563cdcefd385a91d7b77fcfc258f42a49b5b15a95a0847f0922a5c5\
                            4478fdc9637b4d6724923f769d13801631321ee8959b83ec5108ae7ac9bd8310b0\
                            21b9daffc173f4fc69462a10f488aef7c9c2c2e593ad0a2b8a7c7355151552a4\
                            80b44902598949662954d322649fc8c5e5f6c6227277921fcb6209236ce9b0fdc8\
                            96995603e1c3a54698a205210dc5423f75caaed37710ad90cc2d76fb573b51a1\
                            8715bd4c9b274362727bc4499eeb8e7f7d00fedc0e3753e3b28d0ff2cb009d3be0\
                            f52c30d213cf4db4e45830ef44d474cb1ed54682121b324d9d6bd22dfb8f346f\
                            023515df76da1582937d372970c05e17e8810c2cbcf23c7dde44f4dd2dea898c1e\
                            84d2b4d8d5a4c63f560b9783042927241bfaa9cf3f20c60045902f3b5d4f94a7\
                            80ea348c1f4f7c200424145acf7ea6f2dcb8b98d4f6e2ae4bc836364095fc8c752\
                            26de91d7da6a25cb918b7b2fba3cf756670388631789742e13a14b1f6d429b76\
                            fffdb148a7586ee95e143caaaeba53dca2d8bbbaa6e3375f7cba494b663a019fe2\
                            8ba1d8e1c08749c4c6b2f3084c5b9affdf4224639918c25c1a160a3310429285\
                            040d883e93ca8a20c979f16166cca152df1af3891f5e35fc519c04159d5123be47\
                            19598ffabc03d6c08e73e4319638a07ec21647b9c933d2212e2efdda2e78873a\
                            bbae7d47a3905764c0f96a39600a880fce278ddcdf68b51ce8958c675519b3f834\
                            cb2905a26cc8c757d17f495957d8bbddaaef4c4b17fc9771923d070ac0311df2\
                            eaeb9821c9d42f96dd5be73f3a5ddd3bd47a4df6c1309677249a30d3d6db7b4634\
                            6970ffcd958c6d653e9ace5adddd8cd359b12aef678cad77239ce63e0cb2fffd\
                            487d1fc62e447f1636d829bd6fbe425e8f21fe391a9f1194c88905c8eda08fb6d6\
                            b53029cf73e215589a25da9daacf2356d4eeb10f4acc92fa66a2ca635247936f\
                            ac3988b5bf8ec792c5192328038218b651c6b7036014816bc06427fdd6a96bf031\
                            6ddc19223266ae197fe63ac97d25add5a1e8edc356ac599638cd2b0b67b87b20\
                            a940afe3bc6e6a88a3b0f668794ce91601c44f98aee43d09a914f1372735684785\
                            46df5832344e249b5d2134852a6e2591b4bd25288dbaee8068b99105575c693f\
                            8c6570ab8f5b08912e5ae256f6945d9c092bd448cd17a1085036b503c7df117f0b\
                            d124f0273725c345cce220613a2a43aceb552146b057375737f1e9f7491b0534\
                            bec2be7cbd06d34a618a9253b24b52c90c741cc2169d22fcf8dc0005cdb4ce3676\
                            0fa798382cc21992a4bed890fe330f1373dbbdafb07300f7ba548eab180c168a\
                            9aa9040d85e3e11e1f8334ce7c6b3963b38f4afa8e5d4b935976e68724f112fabc\
                            96b77499c26c9eb95049911a49592d44176e82e20609cb0c77b70f34cb8eb025\
                            f65773b38e5ed71971b85cc0a1e4187db5646c1824888306d7f3bfa4bc28bc2874\
                            f61e4c7b472c52a56fbab53fb9d1a12dc0b9b2987ee3d573aa868b76164725c8\
                            6caf4de1af441fe215435d88b26e4ab2229c519cf874c336bd6121825c7b681e";
    let secret_key_text = "13131313131313131313131313131313";
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
        FullPacket::<U33, U20, _>::new(associated_data, secret_key, path, []).unwrap();

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
            let packet = packet.left().unwrap();
            let local = packet.accept(secret).unwrap();
            match packet.process(&[], &local).unwrap() {
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
