use super::{
    OnionPacketVersion, PseudoRandomStream, OnionPacketDescription,
// OnionPacket, Processed, MAX_HOPS_NUMBER, PayloadHmac,
};
use generic_array::{GenericArray, typenum::U33};

#[test]
fn packet() {
    use secp256k1::{PublicKey, SecretKey};
    use sha2::Sha256;
    use chacha::ChaCha;

    impl PseudoRandomStream for ChaCha {
        fn seed<T>(v: T) -> Self
        where
            T: AsRef<[u8]>,
        {
            let mut array = [0; 32];
            array.copy_from_slice(v.as_ref());
            ChaCha::new_chacha20(&array, &[0u8; 8])
        }
    }

    let reference_hmac_text = "65f21f9190c70217774a6fbaaa7d63ad64199f4664813b955cff954949076dcf";
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
    let path = public_keys_texts
        .iter()
        .enumerate()
        .map(|(i, &d)| {
            let pk = PublicKey::from_slice(hex::decode(d).unwrap().as_slice()).unwrap();
            let x = i as u8;
            let payload = GenericArray::<_, U33>::from_slice(&[
                0, // realm
                x, x, x, x, x, x, x, x, 0, 0, 0, 0, 0, 0, 0, x, 0, 0, 0, x, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
            .clone();
            (pk, payload)
        })
        .collect::<Vec<_>>();

    let description = OnionPacketDescription::new(
        OnionPacketVersion::_0,
        secret_key,
        path.into_iter(),
        associated_data,
    );
    let packet = description.packet::<Sha256, ChaCha>().unwrap();
    assert_eq!(hex::encode(packet.hmac), reference_hmac_text);
}
