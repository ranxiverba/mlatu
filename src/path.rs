use generic_array::{GenericArray, ArrayLength};
use std::ops::BitXorAssign;
use keystream::KeyStream;

#[cfg(feature = "serde-support")]
use serde::{Serialize, Deserialize};

#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    #[cfg_attr(
        feature = "serde-support",
        serde(bound(
            serialize = "GenericArray<u8, L>: Serialize",
            deserialize = "GenericArray<u8, L>: Deserialize<'de>"
        ))
    )]
    pub data: GenericArray<u8, L>,
    #[cfg_attr(
        feature = "serde-support",
        serde(bound(
            serialize = "GenericArray<u8, M>: Serialize",
            deserialize = "GenericArray<u8, M>: Deserialize<'de>"
        ))
    )]
    pub hmac: GenericArray<u8, M>,
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

impl<L, M> Default for PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    fn default() -> Self {
        PayloadHmac {
            data: Default::default(),
            hmac: Default::default(),
        }
    }
}

impl<L, M> PayloadHmac<L, M>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    pub fn size() -> usize {
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

#[cfg_attr(feature = "serde-support", derive(Serialize, Deserialize))]
pub struct Path<L, M, N>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    #[cfg_attr(
        feature = "serde-support",
        serde(bound(
            serialize = "PayloadHmac<L, M>: Serialize",
            deserialize = "PayloadHmac<L, M>: Deserialize<'de>"
        ))
    )]
    raw: GenericArray<PayloadHmac<L, M>, N>,
}

impl<L, M, N> Path<L, M, N>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    pub fn size() -> usize {
        N::to_usize()
    }

    pub fn new() -> Self {
        Path {
            raw: GenericArray::<PayloadHmac<L, M>, N>::default(),
        }
    }

    pub fn push(&mut self, item: PayloadHmac<L, M>) {
        for i in (1..Self::size()).rev() {
            self.raw[i] = self.raw[i - 1].clone();
        }
        self.raw[0] = item;
    }

    pub fn pop(&mut self) -> PayloadHmac<L, M> {
        let item = self.raw[0].clone();

        for i in 1..Self::size() {
            self.raw[i - 1] = self.raw[i].clone();
        }
        self.raw[Self::size() - 1] = PayloadHmac::default();
        item
    }
}

impl<L, M, N> AsRef<[PayloadHmac<L, M>]> for Path<L, M, N>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    fn as_ref(&self) -> &[PayloadHmac<L, M>] {
        self.raw.as_ref()
    }
}

impl<L, M, N> AsMut<[PayloadHmac<L, M>]> for Path<L, M, N>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
{
    fn as_mut(&mut self) -> &mut [PayloadHmac<L, M>] {
        self.raw.as_mut()
    }
}

impl<'a, L, M, N, I> BitXorAssign<&'a mut I> for Path<L, M, N>
where
    L: ArrayLength<u8>,
    M: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, M>>,
    I: KeyStream,
{
    fn bitxor_assign(&mut self, rhs: &'a mut I) {
        self.as_mut().iter_mut().for_each(|x| *x ^= rhs);
    }
}

mod implementations {
    use super::{PayloadHmac, Path};
    use generic_array::ArrayLength;
    use std::fmt;

    impl<L, M> fmt::Debug for PayloadHmac<L, M>
    where
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("PayloadHmac")
                .field("data", &self.data)
                .field("hmac", &self.hmac)
                .finish()
        }
    }

    impl<L, M> PartialEq for PayloadHmac<L, M>
    where
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.data.eq(&other.data) && self.hmac.eq(&other.hmac)
        }
    }

    impl<L, M> Eq for PayloadHmac<L, M>
    where
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
    {
    }

    impl<L, M, N> fmt::Debug for Path<L, M, N>
    where
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, M>>,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_list().entries(&self.raw).finish()
        }
    }

    impl<L, M, N> PartialEq for Path<L, M, N>
    where
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, M>>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.raw.eq(&other.raw)
        }
    }

    impl<L, M, N> Eq for Path<L, M, N>
    where
        L: ArrayLength<u8>,
        M: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, M>>,
    {
    }
}
