use super::key::KeyType;
use super::path::{PayloadHmac, Path};

use generic_array::{GenericArray, ArrayLength};
use abstract_cryptography::{Array, SecretKey, PublicKey, TagError};
use crypto_mac::Mac;
use digest::{Input, FixedOutput};
use keystream::SeekableKeyStream;
use either::Either;
use std::marker::PhantomData;

pub trait PseudoRandomStream {
    fn seed<T>(v: T) -> Self
    where
        T: AsRef<[u8]>;
}

pub struct OnionPacket<A, S, C, D, L, M, N>
where
    A: SecretKey,
    S: PseudoRandomStream + SeekableKeyStream,
    C: Mac<OutputSize = M>,
    D: Default + Input + FixedOutput<OutputSize = M>,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    ephemeral_public_key: A::PublicKey,
    routing_info: Path<L, M, N>,
    hmac: GenericArray<u8, M>,
    phantom_data: PhantomData<(S, C, D)>,
}

impl<A, S, C, D, L, M, N> OnionPacket<A, S, C, D, L, M, N>
where
    A: SecretKey + Array,
    A::PublicKey: Clone,
    S: PseudoRandomStream + SeekableKeyStream,
    C: Mac<OutputSize = M>,
    D: Default + Input + FixedOutput<OutputSize = M>,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    pub fn new<T, H>(
        associated_data: T,
        initial_hmac: GenericArray<u8, M>,
        session_key: A,
        route: H,
    ) -> Result<Self, A::Error>
    where
        T: AsRef<[u8]>,
        H: Iterator<Item = (A::PublicKey, GenericArray<u8, L>)>,
    {
        let base_point = A::PublicKey::base_point();
        let contexts = A::contexts();
        let public_key = session_key.paired(&contexts.0);

        let initial = (
            Vec::with_capacity(Path::<L, M, N>::size()),
            Vec::with_capacity(Path::<L, M, N>::size()),
            session_key,
            public_key.clone(),
        );

        let mut route = route;
        let (shared_secrets, payloads) = route
            .try_fold(
                initial,
                |(mut s, mut p, mut secret, public), (path_point, payload)| {
                    let temp = secret.dh(&contexts.1, &path_point)?;
                    let result = D::default().chain(&temp.serialize()[..]).fixed_result();
                    let blinding = D::default()
                        .chain(&public.serialize()[..])
                        .chain(&result)
                        .fixed_result();
                    secret.mul_assign(&blinding)?;
                    let public = secret.dh(&contexts.1, &base_point)?;

                    s.push(result);
                    p.push(payload);
                    Ok((s, p, secret, public))
                },
            )
            .map(|(s, p, _, _)| (s, p))?;

        let mut hmac = initial_hmac;
        let mut routing_info = Path::<L, D::OutputSize, N>::new();

        let length = shared_secrets.len();
        for i in 0..length {
            let rho = KeyType::Rho.key::<_, C>(&shared_secrets[i]);
            let mut s = S::seed(rho);
            let size = PayloadHmac::<L, M>::size();
            s.seek_to((size * (Path::<L, M, N>::size() - i)) as _)
                .unwrap();
            let start = Path::<L, M, N>::size() - length;
            routing_info.as_mut()[start..(start + i + 1)]
                .iter_mut()
                .for_each(|x| *x ^= &mut s);
        }

        payloads
            .into_iter()
            .enumerate()
            .rev()
            .for_each(|(index, payload)| {
                routing_info.push(PayloadHmac {
                    data: payload,
                    hmac: hmac.clone(),
                });

                let rho = KeyType::Rho.key::<_, C>(&shared_secrets[index]);
                let mut stream = S::seed(rho);
                routing_info ^= &mut stream;

                let mu = KeyType::Mu.key::<_, C>(&shared_secrets[index]);
                hmac = routing_info.calc_hmac::<C, _>(&mu, &associated_data);
            });

        Ok(OnionPacket {
            ephemeral_public_key: public_key,
            routing_info: routing_info,
            hmac: hmac,
            phantom_data: PhantomData,
        })
    }

    pub fn process<T>(
        self,
        associated_data: T,
        secret_key: A,
    ) -> Result<(Self, PayloadHmac<L, M>), Either<A::Error, TagError>>
    where
        T: AsRef<[u8]>,
    {
        let contexts = A::contexts();

        let (shared_secret, next_dh_key) = {
            let public_key = self.ephemeral_public_key;
            let temp = secret_key
                .dh(&contexts.1, &public_key)
                .map_err(Either::Left)?;
            let shared_secret = D::default().chain(temp.serialize()).fixed_result();
            let dh_key = public_key;
            let blinding = D::default()
                .chain(dh_key.serialize())
                .chain(&shared_secret)
                .fixed_result();
            let next_dh_key = A::copy(blinding)
                .dh(&contexts.1, &dh_key)
                .map_err(Either::Left)?;
            (shared_secret, next_dh_key)
        };

        let (mut routing_info, hmac) = (self.routing_info, self.hmac);

        let mu = KeyType::Mu.key::<_, C>(&shared_secret);
        let hmac_received = routing_info.calc_hmac::<C, _>(&mu, associated_data);

        if hmac_received != hmac {
            Err(Either::Right(TagError))
        } else {
            let rho = KeyType::Rho.key::<_, C>(&shared_secret);
            let mut stream = S::seed(rho);

            let mut item = routing_info.pop();
            item ^= &mut stream;
            routing_info ^= &mut stream;

            let next = OnionPacket {
                ephemeral_public_key: next_dh_key,
                routing_info: routing_info,
                hmac: item.hmac.clone(),
                phantom_data: PhantomData,
            };

            Ok((next, item))
        }
    }

    pub fn hmac(&self) -> GenericArray<u8, M> {
        self.hmac.clone()
    }
}

#[cfg(feature = "serde")]
mod serde_m {
    use super::{OnionPacket, Path, PayloadHmac, PseudoRandomStream};

    use generic_array::{GenericArray, ArrayLength};
    use abstract_cryptography::{Array, SecretKey, PublicKey};
    use crypto_mac::Mac;
    use digest::{Input, FixedOutput};
    use keystream::SeekableKeyStream;
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use std::marker::PhantomData;
    use std::fmt;

    impl<A, S, C, D, L, M, N> Serialize for OnionPacket<A, S, C, D, L, M, N>
    where
        A: SecretKey + Array,
        A::PublicKey: Clone,
        S: PseudoRandomStream + SeekableKeyStream,
        C: Mac<OutputSize = M>,
        D: Default + Input + FixedOutput<OutputSize = M>,
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, M>>,
    {
        fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
        where
            Ser: Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(3)?;
            tuple.serialize_element(&self.ephemeral_public_key.serialize())?;
            tuple.serialize_element(&self.routing_info)?;
            tuple.serialize_element(&self.hmac)?;
            tuple.end()
        }
    }

    impl<'de, A, S, C, D, L, M, N> Deserialize<'de> for OnionPacket<A, S, C, D, L, M, N>
    where
        A: SecretKey + Array,
        A::PublicKey: Clone,
        A::Error: fmt::Display,
        S: PseudoRandomStream + SeekableKeyStream,
        C: Mac<OutputSize = M>,
        D: Default + Input + FixedOutput<OutputSize = M>,
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, M>>,
    {
        fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
        where
            De: Deserializer<'de>,
        {
            use serde::de::{Visitor, SeqAccess, Error};

            struct V<A, S, C, D, L, M, N>
            where
                A: SecretKey + Array,
                A::PublicKey: Clone,
                A::Error: fmt::Display,
                S: PseudoRandomStream + SeekableKeyStream,
                C: Mac<OutputSize = M>,
                D: Default + Input + FixedOutput<OutputSize = M>,
                L: ArrayLength<u8>,
                M: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, M>>,
            {
                phantom_data: PhantomData<(A, S, C, D, L, M, N)>,
            }

            impl<'de, A, S, C, D, L, M, N> Visitor<'de> for V<A, S, C, D, L, M, N>
            where
                A: SecretKey + Array,
                A::PublicKey: Clone,
                A::Error: fmt::Display,
                S: PseudoRandomStream + SeekableKeyStream,
                C: Mac<OutputSize = M>,
                D: Default + Input + FixedOutput<OutputSize = M>,
                L: ArrayLength<u8>,
                M: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, M>>,
            {
                type Value = OnionPacket<A, S, C, D, L, M, N>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "bytes")
                }

                fn visit_seq<Seq>(self, mut sequence: Seq) -> Result<Self::Value, Seq::Error>
                where
                    Seq: SeqAccess<'de>,
                {
                    let k: GenericArray<u8, <A::PublicKey as PublicKey>::Length> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let p: Path<L, M, N> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let m: GenericArray<u8, M> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;

                    let public_key =
                        PublicKey::from_raw(k).map_err(|e| Error::custom(format!("{}", e)))?;

                    Ok(OnionPacket {
                        ephemeral_public_key: public_key,
                        routing_info: p,
                        hmac: m,
                        phantom_data: PhantomData,
                    })
                }
            }

            deserializer.deserialize_tuple(
                3,
                V {
                    phantom_data: PhantomData::<(A, S, C, D, L, M, N)>,
                },
            )
        }
    }
}
