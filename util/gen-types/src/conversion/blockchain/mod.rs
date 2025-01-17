#[cfg(feature = "std")]
mod std_env;

use crate::{borrow::ToOwned, bytes::Bytes, generated::packed, prelude::*, vec::Vec};

impl Pack<packed::Byte32> for [u8; 32] {
    fn pack(&self) -> packed::Byte32 {
        packed::Byte32::from_slice(&self[..]).expect("impossible: fail to pack [u8; 32]")
    }
}

impl Pack<packed::ProposalShortId> for [u8; 10] {
    fn pack(&self) -> packed::ProposalShortId {
        packed::ProposalShortId::from_slice(&self[..])
            .expect("impossible: fail to pack to ProposalShortId")
    }
}

impl Pack<packed::Bytes> for Bytes {
    fn pack(&self) -> packed::Bytes {
        let len = (self.len() as u32).to_le_bytes();
        let mut v = Vec::with_capacity(4 + self.len());
        v.extend_from_slice(&len[..]);
        v.extend_from_slice(&self[..]);
        packed::Bytes::new_unchecked(v.into())
    }
}

impl<'r> Unpack<Bytes> for packed::BytesReader<'r> {
    fn unpack(&self) -> Bytes {
        Bytes::from(self.raw_data().to_owned())
    }
}

impl Unpack<Bytes> for packed::Bytes {
    fn unpack(&self) -> Bytes {
        self.raw_data()
    }
}

impl_conversion_for_vector!(Bytes, BytesVec, BytesVecReader);
impl_conversion_for_packed_optional_pack!(Byte32, Byte32Opt);
impl_conversion_for_packed_optional_pack!(CellOutput, CellOutputOpt);
impl_conversion_for_packed_optional_pack!(Script, ScriptOpt);
impl_conversion_for_packed_iterator_pack!(ProposalShortId, ProposalShortIdVec);
impl_conversion_for_packed_iterator_pack!(Bytes, BytesVec);
impl_conversion_for_packed_iterator_pack!(Transaction, TransactionVec);
impl_conversion_for_packed_iterator_pack!(OutPoint, OutPointVec);
impl_conversion_for_packed_iterator_pack!(CellDep, CellDepVec);
impl_conversion_for_packed_iterator_pack!(CellOutput, CellOutputVec);
impl_conversion_for_packed_iterator_pack!(CellInput, CellInputVec);
impl_conversion_for_packed_iterator_pack!(UncleBlock, UncleBlockVec);
impl_conversion_for_packed_iterator_pack!(Header, HeaderVec);
impl_conversion_for_packed_iterator_pack!(Byte32, Byte32Vec);
