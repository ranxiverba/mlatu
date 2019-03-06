use super::key::KeyType;
use super::path::{PayloadHmac, Path};

use generic_array::{GenericArray, ArrayLength};
use abstract_cryptography::{Array, SecretKey, PublicKey, TagError};
use digest::{Input, FixedOutput, BlockInput, Reset};
use keystream::SeekableKeyStream;
use either::Either;

#[derive(Debug, Eq, PartialEq)]
pub enum OnionPacketVersion {
    _0 = 0,
}

pub trait PseudoRandomStream {
    fn seed<T>(v: T) -> Self
    where
        T: AsRef<[u8]>;
}

pub struct OnionPacket<A, L, M, N>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    version: OnionPacketVersion,
    ephemeral_public_key: A::PublicKey,
    routing_info: Path<L, M, N>,
    hmac: GenericArray<u8, M>,
}

impl<A, L, M, N> OnionPacket<A, L, M, N>
where
    A: SecretKey + Clone + Array,
    A::PublicKey: Clone,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    pub fn new<T, H, S, D>(
        version: OnionPacketVersion,
        session_key: A,
        route: H,
        associated_data: T,
    ) -> Result<Self, A::Error>
    where
        T: AsRef<[u8]>,
        H: Iterator<Item = (A::PublicKey, GenericArray<u8, L>)>,
        S: PseudoRandomStream + SeekableKeyStream,
        D: Input + FixedOutput<OutputSize = M> + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
        D::OutputSize: ArrayLength<u8>,
    {
        let base_point = A::PublicKey::base_point();
        let contexts = A::contexts();
        let public_key = session_key.paired(&contexts.0);

        let initial = (
            Vec::with_capacity(Path::<L, M, N>::size()),
            Vec::with_capacity(Path::<L, M, N>::size()),
            session_key.clone(),
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

        let mut hmac = GenericArray::<u8, D::OutputSize>::default();
        let mut routing_info = Path::<L, D::OutputSize, N>::new();

        let length = shared_secrets.len();
        for i in 0..length {
            let rho = KeyType::Rho.key::<_, D>(&shared_secrets[i]);
            let mut s = S::seed(rho);
            let size = PayloadHmac::<L, D::OutputSize>::size();
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

                let rho = KeyType::Rho.key::<_, D>(&shared_secrets[index]);
                let mut stream = S::seed(rho);
                routing_info ^= &mut stream;

                let mu = KeyType::Mu.key::<_, D>(&shared_secrets[index]);
                hmac = routing_info.calc_hmac::<D, _>(&mu, &associated_data);
            });

        Ok(OnionPacket {
            version: version,
            ephemeral_public_key: public_key,
            routing_info: routing_info,
            hmac: hmac,
        })
    }

    pub fn process<T, S, D>(
        self,
        associated_data: T,
        secret_key: A,
    ) -> Result<(Self, PayloadHmac<L, M>), Either<A::Error, TagError>>
    where
        T: AsRef<[u8]>,
        S: PseudoRandomStream + SeekableKeyStream,
        D: Input + FixedOutput<OutputSize = M> + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
    {
        let contexts = A::contexts();

        let public_key = self.ephemeral_public_key;
        let temp = secret_key
            .dh(&contexts.1, &public_key)
            .map_err(Either::Left)?;
        let shared_secret = D::default().chain(temp.serialize()).fixed_result();

        let (version, mut routing_info, hmac) = (self.version, self.routing_info, self.hmac);

        let mu = KeyType::Mu.key::<_, D>(&shared_secret);
        let hmac_received = routing_info.calc_hmac::<D, _>(&mu, associated_data);

        if hmac_received != hmac {
            Err(Either::Right(TagError))
        } else {
            let rho = KeyType::Rho.key::<_, D>(&shared_secret);
            let mut stream = S::seed(rho);

            let mut item = routing_info.pop();
            item ^= &mut stream;
            routing_info ^= &mut stream;

            let dh_key = public_key;
            let blinding = D::default()
                .chain(dh_key.serialize())
                .chain(shared_secret)
                .fixed_result();
            let next_dh_key = A::copy(blinding)
                .dh(&contexts.1, &dh_key)
                .map_err(Either::Left)?;

            let next = OnionPacket {
                version: version,
                ephemeral_public_key: next_dh_key,
                routing_info: routing_info,
                hmac: item.hmac.clone(),
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
    use super::{OnionPacket, OnionPacketVersion, Path, PayloadHmac};

    use abstract_cryptography::{Array, SecretKey, PublicKey};
    use generic_array::{GenericArray, ArrayLength};
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use std::marker::PhantomData;
    use std::fmt;

    impl<A, L, M, N> Serialize for OnionPacket<A, L, M, N>
    where
        A: SecretKey + Clone + Array,
        A::PublicKey: Clone,
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, M>>,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::SerializeTuple;

            let version = match &self.version {
                &OnionPacketVersion::_0 => 0u8,
            };

            let mut tuple = serializer.serialize_tuple(4)?;
            tuple.serialize_element(&version)?;
            tuple.serialize_element(&self.ephemeral_public_key.serialize())?;
            tuple.serialize_element(&self.routing_info)?;
            tuple.serialize_element(&self.hmac)?;
            tuple.end()
        }
    }

    impl<'de, A, L, M, N> Deserialize<'de> for OnionPacket<A, L, M, N>
    where
        A: 'de + SecretKey + Clone + Array,
        A::PublicKey: Clone,
        A::Error: fmt::Display,
        L: 'de + ArrayLength<u8>,
        M: 'de + ArrayLength<u8>,
        N: 'de + ArrayLength<PayloadHmac<L, M>>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{Visitor, SeqAccess, Error};

            struct V<A, L, M, N>
            where
                A: SecretKey + Clone + Array,
                A::PublicKey: Clone,
                A::Error: fmt::Display,
                L: ArrayLength<u8>,
                M: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, M>>,
            {
                phantom_data: PhantomData<(A, L, M, N)>,
            }

            impl<'de, A, L, M, N> Visitor<'de> for V<A, L, M, N>
            where
                A: 'de + SecretKey + Clone + Array,
                A::PublicKey: Clone,
                A::Error: fmt::Display,
                L: 'de + ArrayLength<u8>,
                M: 'de + ArrayLength<u8>,
                N: 'de + ArrayLength<PayloadHmac<L, M>>,
            {
                type Value = OnionPacket<A, L, M, N>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "bytes")
                }

                fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
                where
                    S: SeqAccess<'de>,
                {
                    let v: u8 = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let k: GenericArray<u8, <A::PublicKey as PublicKey>::Length> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let p: Path<L, M, N> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let m: GenericArray<u8, M> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;

                    let version = match v {
                        0 => Ok(OnionPacketVersion::_0),
                        _ => Err(Error::custom("unknown version")),
                    }?;

                    let public_key =
                        PublicKey::from_raw(k).map_err(|e| Error::custom(format!("{}", e)))?;

                    Ok(OnionPacket {
                        version: version,
                        ephemeral_public_key: public_key,
                        routing_info: p,
                        hmac: m,
                    })
                }
            }

            deserializer.deserialize_tuple(
                4,
                V {
                    phantom_data: PhantomData::<(A, L, M, N)>,
                },
            )
        }
    }
}
