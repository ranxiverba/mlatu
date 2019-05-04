use super::path::{PayloadHmac, Path};
use super::sphinx::Sphinx;

use generic_array::{GenericArray, ArrayLength};
use abstract_cryptography::{Array, SecretKey};
use keystream::SeekableKeyStream;
use std::{fmt, error::Error};

#[derive(Debug)]
pub enum ProcessingError {
    MacMismatch,
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ProcessingError::MacMismatch => write!(f, "message authentication code mismatch"),
        }
    }
}

impl Error for ProcessingError {
}

pub struct LocalStuff<A>
where
    A: SecretKey + Array,
{
    this_id: A::PublicKey,
    next_id: A::PublicKey,
    shared_secret: GenericArray<u8, <A as Array>::Length>,
}

impl<A> LocalStuff<A>
where
    A: SecretKey + Array,
{
    pub fn this_id(&self) -> &A::PublicKey {
        &self.this_id
    }

    pub fn next_id(&self) -> &A::PublicKey {
        &self.next_id
    }

    pub fn shared_secret(&self) -> &GenericArray<u8, <A as Array>::Length> {
        &self.shared_secret
    }
}

pub enum Processed<B, L, N, P>
where
    B: Sphinx,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>>,
    P: AsMut<[u8]>,
{
    Forward {
        data: GenericArray<u8, L>,
        next: Packet<B, L, N, P>,
    },
    Exit {
        data: GenericArray<u8, L>,
        message: P,
    },
}

pub struct Packet<B, L, N, P>
where
    B: Sphinx,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>>,
    P: AsMut<[u8]>,
{
    public_key: <B::AsymmetricKey as SecretKey>::PublicKey,
    routing_info: Path<L, B::MacLength, N>,
    hmac: GenericArray<u8, B::MacLength>,
    message: P,
}

impl<B, L, N, P> Packet<B, L, N, P>
where
    B: Sphinx,
    B::AsymmetricKey: Array,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>>,
    P: AsMut<[u8]>,
{
    pub fn new<T, H>(
        associated_data: T,
        session_key: &B::AsymmetricKey,
        route: H,
        message: P,
    ) -> Result<Self, <B::AsymmetricKey as SecretKey>::Error>
    where
        T: AsRef<[u8]>,
        H: Iterator<
            Item = (
                <B::AsymmetricKey as SecretKey>::PublicKey,
                GenericArray<u8, L>,
            ),
        >,
    {
        use keystream::KeyStream;

        let contexts = <B::AsymmetricKey as SecretKey>::contexts();
        let public_key = session_key.paired(&contexts.0);

        let initial = (
            Vec::with_capacity(Path::<L, B::MacLength, N>::size()),
            Vec::with_capacity(Path::<L, B::MacLength, N>::size()),
            <B::AsymmetricKey as Array>::from_inner(session_key.serialize()),
            Array::from_inner(public_key.serialize()),
        );

        let mut route = route;
        let (shared_secrets, payloads) = route
            .try_fold(
                initial,
                |(mut s, mut p, mut secret, public), (path_point, payload)| {
                    let temp = secret.dh(&contexts.1, &path_point)?;
                    let result = B::tau(temp);
                    let blinding = B::blinding(&public, &result);
                    secret.mul_assign(&blinding)?;
                    let public = secret.paired(&contexts.0);

                    s.push(result);
                    p.push(payload);
                    Ok((s, p, secret, public))
                },
            )
            .map(|(s, p, _, _)| (s, p))?;

        let mut hmac = GenericArray::default();
        let mut routing_info = Path::<L, B::MacLength, N>::new();
        let mut message = message;

        let length = shared_secrets.len();
        for i in 0..length {
            let mut s = B::rho(&shared_secrets[i]);
            let size = PayloadHmac::<L, B::MacLength>::size();
            s.seek_to((size * (Path::<L, B::MacLength, N>::size() - i)) as _)
                .unwrap();
            let start = Path::<L, B::MacLength, N>::size() - length;
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

                let mut stream = B::rho(&shared_secrets[index]);
                routing_info ^= &mut stream;

                let mut stream = B::pi(&shared_secrets[index]);
                stream.xor_read(message.as_mut()).unwrap();

                let mu = B::mu(&shared_secrets[index]);
                let mu = routing_info
                    .as_ref()
                    .iter()
                    .fold(mu, |mu, hop| B::chain(B::chain(mu, &hop.data), &hop.hmac));
                let mu = B::chain(mu, associated_data.as_ref());
                hmac = B::output(mu);
            });

        Ok(Packet {
            public_key: public_key,
            routing_info: routing_info,
            hmac: hmac,
            message: message,
        })
    }

    pub fn accept(
        &self,
        secret_key: &B::AsymmetricKey,
    ) -> Result<LocalStuff<B::AsymmetricKey>, <B::AsymmetricKey as SecretKey>::Error> {
        let contexts = <B::AsymmetricKey as SecretKey>::contexts();

        let public_key = &self.public_key;
        let temp = secret_key
            .dh(&contexts.1, public_key)?;
        let shared_secret = B::tau(temp);
        let blinding = B::blinding(public_key, &shared_secret);
        let next_dh_key = <B::AsymmetricKey as Array>::from_inner(blinding)
            .dh(&contexts.1, public_key)?;
        Ok(LocalStuff {
            this_id: Array::from_inner(public_key.serialize()),
            next_id: next_dh_key,
            shared_secret: shared_secret,
        })
    }

    pub fn process<T>(
        self,
        associated_data: T,
        local: &LocalStuff<B::AsymmetricKey>,
    ) -> Result<Processed<B, L, N, P>, ProcessingError>
    where
        T: AsRef<[u8]>,
    {
        use keystream::KeyStream;

        let (mut routing_info, hmac_received, mut message) =
            (self.routing_info, self.hmac, self.message);

        let mu = B::mu(&local.shared_secret());
        let mu = routing_info
            .as_ref()
            .iter()
            .fold(mu, |mu, hop| B::chain(B::chain(mu, &hop.data), &hop.hmac));
        let mu = B::chain(mu, associated_data.as_ref());
        let hmac = B::output(mu);

        if hmac_received != hmac {
            Err(ProcessingError::MacMismatch)
        } else {
            let mut stream = B::rho(&local.shared_secret());
            let mut item = routing_info.pop();
            item ^= &mut stream;
            routing_info ^= &mut stream;

            let mut stream = B::pi(&local.shared_secret());
            stream.xor_read(message.as_mut()).unwrap();

            let PayloadHmac {
                data: item_data,
                hmac: item_hmac,
            } = item;

            if item_hmac == GenericArray::default() {
                Ok(Processed::Exit {
                    data: item_data,
                    message: message,
                })
            } else {
                let next = Packet {
                    public_key: Array::from_inner(local.next_id().serialize()),
                    routing_info: routing_info,
                    hmac: item_hmac,
                    message: message,
                };

                Ok(Processed::Forward {
                    data: item_data,
                    next: next,
                })
            }
        }
    }
}

#[cfg(feature = "serde-support")]
mod serde_m {
    use super::{Packet, Path, PayloadHmac, Sphinx};

    use generic_array::{GenericArray, ArrayLength};
    use abstract_cryptography::{Array, SecretKey};
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use std::marker::PhantomData;
    use std::fmt;

    impl<B, L, N, P> Serialize for Packet<B, L, N, P>
    where
        B: Sphinx,
        B::AsymmetricKey: Array,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: AsMut<[u8]> + Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(4)?;
            tuple.serialize_element(&self.public_key.serialize())?;
            tuple.serialize_element(&self.routing_info)?;
            tuple.serialize_element(&self.hmac)?;
            tuple.serialize_element(&self.message)?;
            tuple.end()
        }
    }

    impl<'de, B, L, N, P> Deserialize<'de> for Packet<B, L, N, P>
    where
        B: Sphinx,
        <B::AsymmetricKey as SecretKey>::Error: fmt::Display,
        B::AsymmetricKey: Array,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: AsMut<[u8]> + for<'d> Deserialize<'d>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{Visitor, SeqAccess, Error};

            struct V<B, L, N, P>
            where
                B: Sphinx,
                <B::AsymmetricKey as SecretKey>::Error: fmt::Display,
                B::AsymmetricKey: Array,
                L: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, B::MacLength>>,
                P: AsMut<[u8]> + for<'d> Deserialize<'d>,
            {
                phantom_data: PhantomData<(B, L, N, P)>,
            }

            impl<'de, B, L, N, P> Visitor<'de> for V<B, L, N, P>
            where
                B: Sphinx,
                <B::AsymmetricKey as SecretKey>::Error: fmt::Display,
                B::AsymmetricKey: Array,
                L: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, B::MacLength>>,
                P: AsMut<[u8]> + for<'d> Deserialize<'d>,
            {
                type Value = Packet<B, L, N, P>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "bytes")
                }

                fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
                where
                    S: SeqAccess<'de>,
                {
                    let k: GenericArray<
                        u8,
                        <<B::AsymmetricKey as SecretKey>::PublicKey as Array>::Length,
                    > = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let p: Path<L, B::MacLength, N> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let m: GenericArray<u8, B::MacLength> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let ms: P = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;

                    let public_key = <B::AsymmetricKey as SecretKey>::check(&k)
                        .map(|()| Array::from_inner(k))
                        .map_err(|e| Error::custom(format!("{}", e)))?;

                    Ok(Packet {
                        public_key: public_key,
                        routing_info: p,
                        hmac: m,
                        message: ms,
                    })
                }
            }

            deserializer.deserialize_tuple(
                4,
                V {
                    phantom_data: PhantomData::<(B, L, N, P)>,
                },
            )
        }
    }
}

mod implementations {
    use super::{Packet, Sphinx, PayloadHmac};
    use generic_array::ArrayLength;
    use abstract_cryptography::{Array, SecretKey};
    use std::fmt;

    impl<B, L, N, P> fmt::Debug for Packet<B, L, N, P>
    where
        B: Sphinx,
        B::AsymmetricKey: Array,
        <B::AsymmetricKey as SecretKey>::PublicKey: fmt::Debug,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: fmt::Debug + AsMut<[u8]>,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("Packet")
                .field("public_key", &self.public_key)
                .field("routing_info", &self.routing_info)
                .field("hmac", &self.hmac)
                .field("message", &self.message)
                .finish()
        }
    }

    impl<B, L, N, P> PartialEq for Packet<B, L, N, P>
    where
        B: Sphinx,
        <B::AsymmetricKey as SecretKey>::PublicKey: PartialEq,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: PartialEq + AsMut<[u8]>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.public_key.eq(&other.public_key) && self.routing_info.eq(&other.routing_info)
            && self.hmac.eq(&other.hmac) && self.message.eq(&other.message)
        }
    }

    impl<B, L, N, P> Eq for Packet<B, L, N, P>
    where
        B: Sphinx,
        <B::AsymmetricKey as SecretKey>::PublicKey: PartialEq,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: PartialEq + AsMut<[u8]>,
    {}
}
