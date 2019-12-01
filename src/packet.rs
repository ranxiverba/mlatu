use super::path::{PayloadHmac, Path};
use super::sphinx::{Sphinx, SharedSecret};

use generic_array::{GenericArray, ArrayLength};
use abstract_cryptography::{Array, SecretKey, TagError};
use keystream::SeekableKeyStream;
use either::Either;
use digest::{Input, FixedOutput};

pub struct LocalData<A>
where
    A: SecretKey + Array,
{
    pub shared_secret: SharedSecret<A>,
}

impl<A> LocalData<A>
where
    A: SecretKey + Array,
{
    pub fn next<B>(
        secret_key: &A,
        this: &A::PublicKey,
    ) -> Result<(Self, A::PublicKey), Either<<A as SecretKey>::Error, <A as Array>::Error>>
    where
        B: Sphinx<AsymmetricKey = A>,
    {
        use self::Either::{Left, Right};

        let contexts = A::contexts();

        let shared_secret = B::tau(secret_key.dh(&contexts.1, this).map_err(Left)?);
        let blinding = A::from_raw(B::blinding(this, &shared_secret))
            .map_err(Right)?;
        let next = blinding.dh(&contexts.1, this)
            .map_err(Left)?;
        Ok((LocalData { shared_secret: shared_secret }, next))
    }

    pub fn digest<D>(&self) -> Self
    where
        D: Default + Input + FixedOutput<OutputSize = A::Length>,
    {
        LocalData {
            shared_secret: D::default().chain(&self.shared_secret).fixed_result(),
        }
    }
}

pub struct GlobalData<A, N>
where
    A: SecretKey + Array,
    N: ArrayLength<SharedSecret<A>>,
{
    pub shared_secrets: GenericArray<SharedSecret<A>, N>,
}

impl<A, N> GlobalData<A, N>
where
    A: SecretKey + Array,
    N: ArrayLength<SharedSecret<A>>,
{
    pub fn new<H, B>(
        session_key: &A,
        path: H,
    ) -> Result<(Self, A::PublicKey), Either<<A as SecretKey>::Error, <A as Array>::Error>>
    where
        H: Iterator<Item = <B::AsymmetricKey as SecretKey>::PublicKey>,
        B: Sphinx<AsymmetricKey = A>,
    {
        use self::Either::{Left, Right};

        let contexts = A::contexts();
        let public_key = session_key.paired(&contexts.0);

        let initial = (
            Vec::with_capacity(N::to_usize()),
            A::from_raw(session_key.serialize()).map_err(Right)?,
            Array::from_raw(public_key.serialize()).map_err(Left)?,
        );

        let mut path = path;
        let shared_secrets = path
            .try_fold(initial, |(mut s, mut secret, public), path_point| {
                let temp = secret.dh(&contexts.1, &path_point)?;
                let result = B::tau(temp);
                let blinding = B::blinding(&public, &result);
                secret.mul_assign(&blinding)?;
                let public = secret.paired(&contexts.0);

                s.push(result);
                Ok((s, secret, public))
            })
            .map(|(s, _, _)| s).map_err(Left)?;

        let mut shared_secrets_array = GenericArray::default();
        shared_secrets_array[0..shared_secrets.len()].clone_from_slice(shared_secrets.as_slice());
        Ok((GlobalData { shared_secrets: shared_secrets_array }, public_key))
    }

    pub fn digest<D>(&self) -> Self
    where
        D: Default + Input + FixedOutput<OutputSize = A::Length>,
    {
        let mut shared_secrets_array = self.shared_secrets.clone();
        shared_secrets_array.as_mut_slice().iter_mut().for_each(|x| {
            *x = D::default().chain(x.as_ref()).fixed_result()
        });
        GlobalData {
            shared_secrets: shared_secrets_array,
        }
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
        next: AuthenticatedMessage<B, L, N, P>,
    },
    Exit {
        data: GenericArray<u8, L>,
        message: P,
    },
}

pub struct AuthenticatedMessage<B, L, N, P>
where
    B: Sphinx,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>>,
    P: AsMut<[u8]>,
{
    routing_info: Path<L, B::MacLength, N>,
    hmac: GenericArray<u8, B::MacLength>,
    message: P,
}

impl<B, L, N, P> AuthenticatedMessage<B, L, N, P>
where
    B: Sphinx,
    B::AsymmetricKey: Array,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>> + ArrayLength<SharedSecret<B::AsymmetricKey>>,
    P: AsMut<[u8]>,
{
    pub fn new<T, H>(
        data: GlobalData<B::AsymmetricKey, N>,
        associated_data: T,
        payloads: H,
        message: P,
    ) -> Result<Self, <B::AsymmetricKey as SecretKey>::Error>
    where
        T: AsRef<[u8]>,
        H: Iterator<Item = GenericArray<u8, L>> + DoubleEndedIterator + ExactSizeIterator,
    {
        use keystream::KeyStream;

        let GlobalData { shared_secrets: shared_secrets } = data;
        let mut hmac = GenericArray::default();
        let mut routing_info = Path::<L, B::MacLength, N>::new();
        let mut message = message;

        let length = payloads.len();
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

        payloads.enumerate().rev().for_each(|(index, payload)| {
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

        Ok(AuthenticatedMessage {
            routing_info: routing_info,
            hmac: hmac,
            message: message,
        })
    }

    pub fn process<T>(
        self,
        associated_data: T,
        local: &LocalData<B::AsymmetricKey>,
    ) -> Result<Processed<B, L, N, P>, TagError>
    where
        T: AsRef<[u8]>,
    {
        use keystream::KeyStream;

        let (mut routing_info, hmac_received, mut message) =
            (self.routing_info, self.hmac, self.message);

        let mu = B::mu(&local.shared_secret);
        let mu = routing_info
            .as_ref()
            .iter()
            .fold(mu, |mu, hop| B::chain(B::chain(mu, &hop.data), &hop.hmac));
        let mu = B::chain(mu, associated_data.as_ref());
        let hmac = B::output(mu);

        if hmac_received != hmac {
            Err(TagError)
        } else {
            let mut stream = B::rho(&local.shared_secret);
            let mut item = routing_info.pop();
            item ^= &mut stream;
            routing_info ^= &mut stream;

            let mut stream = B::pi(&local.shared_secret);
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
                let next = AuthenticatedMessage {
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
    use super::{AuthenticatedMessage, Path, PayloadHmac, Sphinx};

    use generic_array::{GenericArray, ArrayLength};
    use abstract_cryptography::{Array, SecretKey};
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use std::marker::PhantomData;
    use std::fmt;

    impl<B, L, N, P> Serialize for AuthenticatedMessage<B, L, N, P>
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

            let mut tuple = serializer.serialize_tuple(3)?;
            tuple.serialize_element(&self.routing_info)?;
            tuple.serialize_element(&self.hmac)?;
            tuple.serialize_element(&self.message)?;
            tuple.end()
        }
    }

    impl<'de, B, L, N, P> Deserialize<'de> for AuthenticatedMessage<B, L, N, P>
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
                type Value = AuthenticatedMessage<B, L, N, P>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "bytes")
                }

                fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
                where
                    S: SeqAccess<'de>,
                {
                    let p: Path<L, B::MacLength, N> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let m: GenericArray<u8, B::MacLength> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let ms: P = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;

                    Ok(AuthenticatedMessage {
                        routing_info: p,
                        hmac: m,
                        message: ms,
                    })
                }
            }

            deserializer.deserialize_tuple(
                3,
                V {
                    phantom_data: PhantomData::<(B, L, N, P)>,
                },
            )
        }
    }
}

mod implementations {
    use super::{AuthenticatedMessage, Sphinx, PayloadHmac, LocalData};
    use generic_array::ArrayLength;
    use abstract_cryptography::{Array, SecretKey};
    use std::fmt;

    impl<B, L, N, P> fmt::Debug for AuthenticatedMessage<B, L, N, P>
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
                .field("routing_info", &self.routing_info)
                .field("hmac", &self.hmac)
                .field("message", &self.message)
                .finish()
        }
    }

    impl<B, L, N, P> PartialEq for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        <B::AsymmetricKey as SecretKey>::PublicKey: PartialEq,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: PartialEq + AsMut<[u8]>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.routing_info.eq(&other.routing_info)
                && self.hmac.eq(&other.hmac)
                && self.message.eq(&other.message)
        }
    }

    impl<B, L, N, P> Eq for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        <B::AsymmetricKey as SecretKey>::PublicKey: PartialEq,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: PartialEq + AsMut<[u8]>,
    {
    }

    impl<A> fmt::Debug for LocalData<A>
    where
        A: SecretKey + Array,
        <A as SecretKey>::PublicKey: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("LocalStuff")
                .field("shared_secret", &self.shared_secret)
                .finish()
        }
    }

    impl<A> PartialEq for LocalData<A>
    where
        A: SecretKey + Array,
        <A as SecretKey>::PublicKey: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.shared_secret.eq(&other.shared_secret)
        }
    }

    impl<A> Eq for LocalData<A>
    where
        A: SecretKey + Array,
        <A as SecretKey>::PublicKey: PartialEq,
    {
    }
}
