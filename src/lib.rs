#![forbid(unsafe_code)]

#[cfg(test)]
mod test;

use abstract_cryptography::{Array, SecretKey, PublicKey, TagError};
use digest::{Input, FixedOutput, BlockInput, Reset};
use generic_array::{GenericArray, ArrayLength};
use keystream::{KeyStream, SeekableKeyStream};
use std::ops::BitXorAssign;
use either::Either;

#[derive(Debug, Eq, PartialEq)]
pub enum OnionPacketVersion {
    _0 = 0,
}

enum KeyType {
    Rho,
    Mu,
}

impl KeyType {
    pub fn key<T, D>(&self, input: T) -> GenericArray<u8, D::OutputSize>
    where
        T: AsRef<[u8]>,
        D: Input + FixedOutput + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
        D::OutputSize: ArrayLength<u8>,
    {
        use hmac::{Mac, Hmac};

        let key_type = match self {
            &KeyType::Rho => "rho",
            &KeyType::Mu => "mu",
        };

        let mut mac = Hmac::<D>::new_varkey(key_type.as_bytes()).unwrap();
        mac.input(input.as_ref());
        mac.result().code()
    }
}

pub trait PseudoRandomStream {
    fn seed<T>(v: T) -> Self
    where
        T: AsRef<[u8]>;
}

#[derive(Default)]
struct PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    data: GenericArray<u8, L>,
    hmac: GenericArray<u8, M>,
}

impl<L, M> Clone for PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        PayloadHmac {
            data: self.data.clone(),
            hmac: self.hmac.clone(),
        }
    }
}

impl<L, M> PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    fn zero() -> Self {
        PayloadHmac {
            data: Default::default(),
            hmac: Default::default(),
        }
    }

    fn size() -> usize {
        L::to_usize() + M::to_usize()
    }
}

impl<'a, L, M, I> BitXorAssign<&'a mut I> for PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    I: KeyStream,
{
    fn bitxor_assign(&mut self, rhs: &'a mut I) {
        rhs.xor_read(self.data.as_mut_slice()).unwrap();
        rhs.xor_read(self.hmac.as_mut_slice()).unwrap();
    }
}

const MAX_HOPS_NUMBER: usize = 20;

struct Path<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    raw: [PayloadHmac<L, M>; MAX_HOPS_NUMBER],
}

impl<L, M> Path<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    pub fn new() -> Self {
        Path {
            raw: [
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
                PayloadHmac::<L, M>::zero(),
            ],
        }
    }

    pub fn calc_hmac<D, T>(
        &self,
        mu: &GenericArray<u8, M>,
        associated_data: T,
    ) -> GenericArray<u8, M>
    where
        D: Input + FixedOutput<OutputSize = M> + BlockInput + Reset + Clone + Default,
        D::BlockSize: ArrayLength<u8> + Clone,
        D::OutputSize: ArrayLength<u8>,
        T: AsRef<[u8]>,
    {
        use hmac::{Mac, Hmac};

        let mac = Hmac::<D>::new_varkey(&mu).unwrap();
        let mut mac = self.as_ref().iter().fold(mac, |mut mac, hop| {
            mac.input(&hop.data);
            mac.input(&hop.hmac);
            mac
        });
        mac.input(associated_data.as_ref());
        mac.result().code()
    }

    pub fn push(&mut self, item: PayloadHmac<L, M>) {
        for i in (1..MAX_HOPS_NUMBER).rev() {
            self.raw[i] = self.raw[i - 1].clone();
        }
        self.raw[0] = item;
    }

    pub fn pop(&mut self) -> PayloadHmac<L, M> {
        let item = self.raw[0].clone();

        for i in 1..MAX_HOPS_NUMBER {
            self.raw[i - 1] = self.raw[i].clone();
        }
        self.raw[MAX_HOPS_NUMBER - 1] = PayloadHmac::zero();
        item
    }
}

impl<L, M> AsRef<[PayloadHmac<L, M>]> for Path<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    fn as_ref(&self) -> &[PayloadHmac<L, M>] {
        self.raw.as_ref()
    }
}

impl<L, M> AsMut<[PayloadHmac<L, M>]> for Path<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    fn as_mut(&mut self) -> &mut [PayloadHmac<L, M>] {
        self.raw.as_mut()
    }
}

impl<'a, L, M, I> BitXorAssign<&'a mut I> for Path<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    I: KeyStream,
{
    fn bitxor_assign(&mut self, rhs: &'a mut I) {
        self.as_mut().iter_mut().for_each(|x| *x ^= rhs);
    }
}

pub struct OnionPacket<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    version: OnionPacketVersion,
    ephemeral_public_key: A::PublicKey,
    routing_info: Path<L, M>,
    hmac: GenericArray<u8, M>,
}

pub enum Processed<A, L, M>
where
    A: SecretKey,
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    ExitNode {
        output: GenericArray<u8, L>,
    },
    MoreHops {
        next: OnionPacket<A, L, M>,
        output: GenericArray<u8, L>,
    },
}

impl<A, L, M> OnionPacket<A, L, M>
where
    A: SecretKey + Clone + Array,
    A::PublicKey: Clone,
    L: ArrayLength<u8> + Clone,
    M: ArrayLength<u8> + Clone,
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
            Vec::with_capacity(MAX_HOPS_NUMBER),
            Vec::with_capacity(MAX_HOPS_NUMBER),
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
        let mut routing_info = Path::<L, D::OutputSize>::new();

        let length = shared_secrets.len();
        for i in 0..length {
            let rho = KeyType::Rho.key::<_, D>(&shared_secrets[i]);
            let mut s = S::seed(rho);
            let size = PayloadHmac::<L, D::OutputSize>::size();
            s.seek_to((size * (MAX_HOPS_NUMBER - i)) as _).unwrap();
            let start = MAX_HOPS_NUMBER - length;
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
    ) -> Result<Processed<A, L, M>, Either<A::Error, TagError>>
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

            if item.hmac == GenericArray::default() {
                Ok(Processed::ExitNode { output: item.data })
            } else {
                let dh_key = public_key;
                let blinding = D::default()
                    .chain(dh_key.serialize())
                    .chain(shared_secret)
                    .fixed_result();
                let next_dh_key = A::copy(blinding)
                    .dh(&contexts.1, &dh_key)
                    .map_err(Either::Left)?;

                Ok(Processed::MoreHops {
                    next: OnionPacket {
                        version: version,
                        ephemeral_public_key: next_dh_key,
                        routing_info: routing_info,
                        hmac: item.hmac,
                    },
                    output: item.data,
                })
            }
        }
    }
}
