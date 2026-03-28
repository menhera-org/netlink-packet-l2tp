// SPDX-License-Identifier: MIT

//! The `netlink-packet-l2tp` crate provides generic netlink packet
//! definitions for Linux L2TP.

mod attribute;
mod constants;
mod message;
mod stats;

#[cfg(test)]
mod test;

pub use self::{
    attribute::{L2tpAttribute, L2tpEncapType, L2tpL2SpecType, L2tpPwType},
    constants::*,
    message::{L2tpCmd, L2tpMessage},
    stats::L2tpStatsAttr,
};
