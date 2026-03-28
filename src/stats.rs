// SPDX-License-Identifier: MIT

use std::mem::size_of_val;

use netlink_packet_core::{
    emit_u64, parse_u64, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

use crate::constants::*;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpStatsAttr {
    TxPackets(u64),
    TxBytes(u64),
    TxErrors(u64),
    RxPackets(u64),
    RxBytes(u64),
    RxSeqDiscards(u64),
    RxOosPackets(u64),
    RxErrors(u64),
    StatsPad,
    RxCookieDiscards(u64),
    RxInvalid(u64),
    Other(DefaultNla),
}

impl Nla for L2tpStatsAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::TxPackets(v)
            | Self::TxBytes(v)
            | Self::TxErrors(v)
            | Self::RxPackets(v)
            | Self::RxBytes(v)
            | Self::RxSeqDiscards(v)
            | Self::RxOosPackets(v)
            | Self::RxErrors(v)
            | Self::RxCookieDiscards(v)
            | Self::RxInvalid(v) => size_of_val(v),
            Self::StatsPad => 0,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::TxPackets(_) => L2TP_ATTR_TX_PACKETS,
            Self::TxBytes(_) => L2TP_ATTR_TX_BYTES,
            Self::TxErrors(_) => L2TP_ATTR_TX_ERRORS,
            Self::RxPackets(_) => L2TP_ATTR_RX_PACKETS,
            Self::RxBytes(_) => L2TP_ATTR_RX_BYTES,
            Self::RxSeqDiscards(_) => L2TP_ATTR_RX_SEQ_DISCARDS,
            Self::RxOosPackets(_) => L2TP_ATTR_RX_OOS_PACKETS,
            Self::RxErrors(_) => L2TP_ATTR_RX_ERRORS,
            Self::StatsPad => L2TP_ATTR_STATS_PAD,
            Self::RxCookieDiscards(_) => L2TP_ATTR_RX_COOKIE_DISCARDS,
            Self::RxInvalid(_) => L2TP_ATTR_RX_INVALID,
            Self::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::TxPackets(v)
            | Self::TxBytes(v)
            | Self::TxErrors(v)
            | Self::RxPackets(v)
            | Self::RxBytes(v)
            | Self::RxSeqDiscards(v)
            | Self::RxOosPackets(v)
            | Self::RxErrors(v)
            | Self::RxCookieDiscards(v)
            | Self::RxInvalid(v) => emit_u64(buffer, *v).unwrap(),
            Self::StatsPad => {}
            Self::Other(v) => v.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for L2tpStatsAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            L2TP_ATTR_TX_PACKETS => Self::TxPackets(
                parse_u64(payload).context("invalid L2TP_ATTR_TX_PACKETS")?,
            ),
            L2TP_ATTR_TX_BYTES => Self::TxBytes(
                parse_u64(payload).context("invalid L2TP_ATTR_TX_BYTES")?,
            ),
            L2TP_ATTR_TX_ERRORS => Self::TxErrors(
                parse_u64(payload).context("invalid L2TP_ATTR_TX_ERRORS")?,
            ),
            L2TP_ATTR_RX_PACKETS => Self::RxPackets(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_PACKETS")?,
            ),
            L2TP_ATTR_RX_BYTES => Self::RxBytes(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_BYTES")?,
            ),
            L2TP_ATTR_RX_SEQ_DISCARDS => Self::RxSeqDiscards(
                parse_u64(payload)
                    .context("invalid L2TP_ATTR_RX_SEQ_DISCARDS")?,
            ),
            L2TP_ATTR_RX_OOS_PACKETS => Self::RxOosPackets(
                parse_u64(payload)
                    .context("invalid L2TP_ATTR_RX_OOS_PACKETS")?,
            ),
            L2TP_ATTR_RX_ERRORS => Self::RxErrors(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_ERRORS")?,
            ),
            L2TP_ATTR_STATS_PAD => Self::StatsPad,
            L2TP_ATTR_RX_COOKIE_DISCARDS => Self::RxCookieDiscards(
                parse_u64(payload)
                    .context("invalid L2TP_ATTR_RX_COOKIE_DISCARDS")?,
            ),
            L2TP_ATTR_RX_INVALID => Self::RxInvalid(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_INVALID")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown stats NLA type {kind}"))?,
            ),
        })
    }
}
