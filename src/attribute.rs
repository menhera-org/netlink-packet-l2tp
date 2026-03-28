// SPDX-License-Identifier: MIT

use std::{
    mem::size_of_val,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::RawFd,
};

use netlink_packet_core::{
    emit_u16, emit_u32, emit_u64, parse_ip, parse_ipv6, parse_string,
    parse_u16, parse_u32, parse_u64, parse_u8, DecodeError, DefaultNla,
    Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
    NLA_F_NESTED,
};

use crate::{constants::*, L2tpStatsAttr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpPwType {
    None,
    EthVlan,
    Eth,
    Ppp,
    PppAc,
    Ip,
    Other(u16),
}

impl From<u16> for L2tpPwType {
    fn from(value: u16) -> Self {
        match value {
            L2TP_PWTYPE_NONE => Self::None,
            L2TP_PWTYPE_ETH_VLAN => Self::EthVlan,
            L2TP_PWTYPE_ETH => Self::Eth,
            L2TP_PWTYPE_PPP => Self::Ppp,
            L2TP_PWTYPE_PPP_AC => Self::PppAc,
            L2TP_PWTYPE_IP => Self::Ip,
            v => Self::Other(v),
        }
    }
}

impl From<L2tpPwType> for u16 {
    fn from(value: L2tpPwType) -> Self {
        match value {
            L2tpPwType::None => L2TP_PWTYPE_NONE,
            L2tpPwType::EthVlan => L2TP_PWTYPE_ETH_VLAN,
            L2tpPwType::Eth => L2TP_PWTYPE_ETH,
            L2tpPwType::Ppp => L2TP_PWTYPE_PPP,
            L2tpPwType::PppAc => L2TP_PWTYPE_PPP_AC,
            L2tpPwType::Ip => L2TP_PWTYPE_IP,
            L2tpPwType::Other(v) => v,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpEncapType {
    Udp,
    Ip,
    Other(u16),
}

impl From<u16> for L2tpEncapType {
    fn from(value: u16) -> Self {
        match value {
            L2TP_ENCAPTYPE_UDP => Self::Udp,
            L2TP_ENCAPTYPE_IP => Self::Ip,
            v => Self::Other(v),
        }
    }
}

impl From<L2tpEncapType> for u16 {
    fn from(value: L2tpEncapType) -> Self {
        match value {
            L2tpEncapType::Udp => L2TP_ENCAPTYPE_UDP,
            L2tpEncapType::Ip => L2TP_ENCAPTYPE_IP,
            L2tpEncapType::Other(v) => v,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpL2SpecType {
    None,
    Default,
    Other(u8),
}

impl From<u8> for L2tpL2SpecType {
    fn from(value: u8) -> Self {
        match value {
            L2TP_L2SPECTYPE_NONE => Self::None,
            L2TP_L2SPECTYPE_DEFAULT => Self::Default,
            v => Self::Other(v),
        }
    }
}

impl From<L2tpL2SpecType> for u8 {
    fn from(value: L2tpL2SpecType) -> Self {
        match value {
            L2tpL2SpecType::None => L2TP_L2SPECTYPE_NONE,
            L2tpL2SpecType::Default => L2TP_L2SPECTYPE_DEFAULT,
            L2tpL2SpecType::Other(v) => v,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpAttribute {
    PwType(L2tpPwType),
    EncapType(L2tpEncapType),
    Offset(u16),
    DataSeq(u16),
    L2SpecType(L2tpL2SpecType),
    L2SpecLen(u8),
    ProtoVersion(u8),
    IfName(String),
    ConnId(u32),
    PeerConnId(u32),
    SessionId(u32),
    PeerSessionId(u32),
    UdpCsum(bool),
    VlanId(u16),
    Cookie(Vec<u8>),
    PeerCookie(Vec<u8>),
    Debug(u32),
    RecvSeq(bool),
    SendSeq(bool),
    LnsMode(bool),
    UsingIpsec(bool),
    RecvTimeout(u64),
    Fd(RawFd),
    IpSaddr(Ipv4Addr),
    IpDaddr(Ipv4Addr),
    UdpSport(u16),
    UdpDport(u16),
    Mtu(u16),
    Mru(u16),
    Stats(Vec<L2tpStatsAttr>),
    Ip6Saddr(Ipv6Addr),
    Ip6Daddr(Ipv6Addr),
    UdpZeroCsum6Tx,
    UdpZeroCsum6Rx,
    Pad,
    Other(DefaultNla),
}

impl L2tpAttribute {
    pub fn if_name(value: impl Into<String>) -> Result<Self, DecodeError> {
        let value = value.into();
        validate_ifname(&value)?;
        Ok(Self::IfName(value))
    }

    pub fn cookie(value: Vec<u8>) -> Result<Self, DecodeError> {
        validate_cookie_len(&value, "L2TP_ATTR_COOKIE")?;
        Ok(Self::Cookie(value))
    }

    pub fn peer_cookie(value: Vec<u8>) -> Result<Self, DecodeError> {
        validate_cookie_len(&value, "L2TP_ATTR_PEER_COOKIE")?;
        Ok(Self::PeerCookie(value))
    }
}

impl Nla for L2tpAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::PwType(_) | Self::EncapType(_) => size_of_val(&0u16),
            Self::Offset(v)
            | Self::DataSeq(v)
            | Self::VlanId(v)
            | Self::UdpSport(v)
            | Self::UdpDport(v)
            | Self::Mtu(v)
            | Self::Mru(v) => size_of_val(v),
            Self::L2SpecType(_) => size_of_val(&0u8),
            Self::L2SpecLen(v) | Self::ProtoVersion(v) => size_of_val(v),
            Self::UdpCsum(v)
            | Self::RecvSeq(v)
            | Self::SendSeq(v)
            | Self::LnsMode(v)
            | Self::UsingIpsec(v) => size_of_val(v),
            Self::IfName(v) => v.len() + 1,
            Self::ConnId(v)
            | Self::PeerConnId(v)
            | Self::SessionId(v)
            | Self::PeerSessionId(v)
            | Self::Debug(v) => size_of_val(v),
            Self::Cookie(v) | Self::PeerCookie(v) => v.len(),
            Self::RecvTimeout(v) => size_of_val(v),
            Self::Fd(v) => size_of_val(v),
            Self::IpSaddr(v) | Self::IpDaddr(v) => v.octets().len(),
            Self::Stats(v) => v.as_slice().buffer_len(),
            Self::Ip6Saddr(v) | Self::Ip6Daddr(v) => v.octets().len(),
            Self::UdpZeroCsum6Tx | Self::UdpZeroCsum6Rx | Self::Pad => 0,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::PwType(_) => L2TP_ATTR_PW_TYPE,
            Self::EncapType(_) => L2TP_ATTR_ENCAP_TYPE,
            Self::Offset(_) => L2TP_ATTR_OFFSET,
            Self::DataSeq(_) => L2TP_ATTR_DATA_SEQ,
            Self::L2SpecType(_) => L2TP_ATTR_L2SPEC_TYPE,
            Self::L2SpecLen(_) => L2TP_ATTR_L2SPEC_LEN,
            Self::ProtoVersion(_) => L2TP_ATTR_PROTO_VERSION,
            Self::IfName(_) => L2TP_ATTR_IFNAME,
            Self::ConnId(_) => L2TP_ATTR_CONN_ID,
            Self::PeerConnId(_) => L2TP_ATTR_PEER_CONN_ID,
            Self::SessionId(_) => L2TP_ATTR_SESSION_ID,
            Self::PeerSessionId(_) => L2TP_ATTR_PEER_SESSION_ID,
            Self::UdpCsum(_) => L2TP_ATTR_UDP_CSUM,
            Self::VlanId(_) => L2TP_ATTR_VLAN_ID,
            Self::Cookie(_) => L2TP_ATTR_COOKIE,
            Self::PeerCookie(_) => L2TP_ATTR_PEER_COOKIE,
            Self::Debug(_) => L2TP_ATTR_DEBUG,
            Self::RecvSeq(_) => L2TP_ATTR_RECV_SEQ,
            Self::SendSeq(_) => L2TP_ATTR_SEND_SEQ,
            Self::LnsMode(_) => L2TP_ATTR_LNS_MODE,
            Self::UsingIpsec(_) => L2TP_ATTR_USING_IPSEC,
            Self::RecvTimeout(_) => L2TP_ATTR_RECV_TIMEOUT,
            Self::Fd(_) => L2TP_ATTR_FD,
            Self::IpSaddr(_) => L2TP_ATTR_IP_SADDR,
            Self::IpDaddr(_) => L2TP_ATTR_IP_DADDR,
            Self::UdpSport(_) => L2TP_ATTR_UDP_SPORT,
            Self::UdpDport(_) => L2TP_ATTR_UDP_DPORT,
            Self::Mtu(_) => L2TP_ATTR_MTU,
            Self::Mru(_) => L2TP_ATTR_MRU,
            Self::Stats(_) => L2TP_ATTR_STATS | NLA_F_NESTED,
            Self::Ip6Saddr(_) => L2TP_ATTR_IP6_SADDR,
            Self::Ip6Daddr(_) => L2TP_ATTR_IP6_DADDR,
            Self::UdpZeroCsum6Tx => L2TP_ATTR_UDP_ZERO_CSUM6_TX,
            Self::UdpZeroCsum6Rx => L2TP_ATTR_UDP_ZERO_CSUM6_RX,
            Self::Pad => L2TP_ATTR_PAD,
            Self::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::PwType(v) => emit_u16(buffer, (*v).into()).unwrap(),
            Self::EncapType(v) => emit_u16(buffer, (*v).into()).unwrap(),
            Self::Offset(v)
            | Self::DataSeq(v)
            | Self::VlanId(v)
            | Self::UdpSport(v)
            | Self::UdpDport(v)
            | Self::Mtu(v)
            | Self::Mru(v) => emit_u16(buffer, *v).unwrap(),
            Self::L2SpecLen(v) | Self::ProtoVersion(v) => buffer[0] = *v,
            Self::L2SpecType(v) => buffer[0] = (*v).into(),
            Self::IfName(v) => {
                buffer[..v.len()].copy_from_slice(v.as_bytes());
                buffer[v.len()] = 0;
            }
            Self::ConnId(v)
            | Self::PeerConnId(v)
            | Self::SessionId(v)
            | Self::PeerSessionId(v)
            | Self::Debug(v) => emit_u32(buffer, *v).unwrap(),
            Self::UdpCsum(v)
            | Self::RecvSeq(v)
            | Self::SendSeq(v)
            | Self::LnsMode(v)
            | Self::UsingIpsec(v) => buffer[0] = u8::from(*v),
            Self::Cookie(v) | Self::PeerCookie(v) => buffer.copy_from_slice(v),
            Self::RecvTimeout(v) => emit_u64(buffer, *v).unwrap(),
            Self::Fd(v) => {
                emit_u32(buffer, u32::try_from(*v).unwrap()).unwrap()
            }
            Self::IpSaddr(v) | Self::IpDaddr(v) => {
                buffer.copy_from_slice(&v.octets())
            }
            Self::Stats(v) => v.as_slice().emit(buffer),
            Self::Ip6Saddr(v) | Self::Ip6Daddr(v) => {
                buffer.copy_from_slice(&v.octets())
            }
            Self::UdpZeroCsum6Tx | Self::UdpZeroCsum6Rx | Self::Pad => {}
            Self::Other(v) => v.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for L2tpAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            L2TP_ATTR_PW_TYPE => Self::PwType(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_PW_TYPE value")?
                    .into(),
            ),
            L2TP_ATTR_ENCAP_TYPE => Self::EncapType(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_ENCAP_TYPE value")?
                    .into(),
            ),
            L2TP_ATTR_OFFSET => Self::Offset(
                parse_u16(payload).context("invalid L2TP_ATTR_OFFSET value")?,
            ),
            L2TP_ATTR_DATA_SEQ => Self::DataSeq(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_DATA_SEQ value")?,
            ),
            L2TP_ATTR_L2SPEC_TYPE => Self::L2SpecType(
                parse_u8(payload)
                    .context("invalid L2TP_ATTR_L2SPEC_TYPE value")?
                    .into(),
            ),
            L2TP_ATTR_L2SPEC_LEN => Self::L2SpecLen(
                parse_u8(payload)
                    .context("invalid L2TP_ATTR_L2SPEC_LEN value")?,
            ),
            L2TP_ATTR_PROTO_VERSION => Self::ProtoVersion(
                parse_u8(payload)
                    .context("invalid L2TP_ATTR_PROTO_VERSION value")?,
            ),
            L2TP_ATTR_IFNAME => Self::IfName(
                parse_ifname(payload)
                    .context("invalid L2TP_ATTR_IFNAME value")?,
            ),
            L2TP_ATTR_CONN_ID => Self::ConnId(
                parse_u32(payload)
                    .context("invalid L2TP_ATTR_CONN_ID value")?,
            ),
            L2TP_ATTR_PEER_CONN_ID => Self::PeerConnId(
                parse_u32(payload)
                    .context("invalid L2TP_ATTR_PEER_CONN_ID value")?,
            ),
            L2TP_ATTR_SESSION_ID => Self::SessionId(
                parse_u32(payload)
                    .context("invalid L2TP_ATTR_SESSION_ID value")?,
            ),
            L2TP_ATTR_PEER_SESSION_ID => Self::PeerSessionId(
                parse_u32(payload)
                    .context("invalid L2TP_ATTR_PEER_SESSION_ID value")?,
            ),
            L2TP_ATTR_UDP_CSUM => Self::UdpCsum(parse_u8(payload)? != 0),
            L2TP_ATTR_VLAN_ID => Self::VlanId(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_VLAN_ID value")?,
            ),
            L2TP_ATTR_COOKIE => Self::Cookie(parse_cookie(payload)?),
            L2TP_ATTR_PEER_COOKIE => {
                Self::PeerCookie(parse_peer_cookie(payload)?)
            }
            L2TP_ATTR_DEBUG => Self::Debug(
                parse_u32(payload).context("invalid L2TP_ATTR_DEBUG value")?,
            ),
            L2TP_ATTR_RECV_SEQ => Self::RecvSeq(parse_u8(payload)? != 0),
            L2TP_ATTR_SEND_SEQ => Self::SendSeq(parse_u8(payload)? != 0),
            L2TP_ATTR_LNS_MODE => Self::LnsMode(parse_u8(payload)? != 0),
            L2TP_ATTR_USING_IPSEC => Self::UsingIpsec(parse_u8(payload)? != 0),
            L2TP_ATTR_RECV_TIMEOUT => {
                Self::RecvTimeout(parse_recv_timeout(payload)?)
            }
            L2TP_ATTR_FD => {
                let fd = parse_u32(payload).context("invalid L2TP_ATTR_FD")?;
                Self::Fd(RawFd::try_from(fd).map_err(
                    |e: std::num::TryFromIntError| {
                        DecodeError::from(e.to_string())
                    },
                )?)
            }
            L2TP_ATTR_IP_SADDR => Self::IpSaddr(parse_ipv4(payload)?),
            L2TP_ATTR_IP_DADDR => Self::IpDaddr(parse_ipv4(payload)?),
            L2TP_ATTR_UDP_SPORT => Self::UdpSport(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_UDP_SPORT value")?,
            ),
            L2TP_ATTR_UDP_DPORT => Self::UdpDport(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_UDP_DPORT value")?,
            ),
            L2TP_ATTR_MTU => Self::Mtu(
                parse_u16(payload).context("invalid L2TP_ATTR_MTU value")?,
            ),
            L2TP_ATTR_MRU => Self::Mru(
                parse_u16(payload).context("invalid L2TP_ATTR_MRU value")?,
            ),
            L2TP_ATTR_STATS => {
                let mut stats = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context("failed to parse L2TP_ATTR_STATS")?;
                    stats.push(L2tpStatsAttr::parse(&nla)?);
                }
                Self::Stats(stats)
            }
            L2TP_ATTR_IP6_SADDR => Self::Ip6Saddr(Ipv6Addr::from(
                parse_ipv6(payload)
                    .context("invalid L2TP_ATTR_IP6_SADDR value")?,
            )),
            L2TP_ATTR_IP6_DADDR => Self::Ip6Daddr(Ipv6Addr::from(
                parse_ipv6(payload)
                    .context("invalid L2TP_ATTR_IP6_DADDR value")?,
            )),
            L2TP_ATTR_UDP_ZERO_CSUM6_TX => Self::UdpZeroCsum6Tx,
            L2TP_ATTR_UDP_ZERO_CSUM6_RX => Self::UdpZeroCsum6Rx,
            L2TP_ATTR_PAD => Self::Pad,
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

fn parse_ipv4(payload: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    match parse_ip(payload)? {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(DecodeError::from(
            "invalid IPv4 attribute value: got IPv6 address",
        )),
    }
}

fn parse_recv_timeout(payload: &[u8]) -> Result<u64, DecodeError> {
    parse_u64(payload).context("invalid L2TP_ATTR_RECV_TIMEOUT value")
}

fn parse_ifname(payload: &[u8]) -> Result<String, DecodeError> {
    let value = parse_string(payload)?;
    validate_ifname(&value)?;
    Ok(value)
}

fn validate_ifname(value: &str) -> Result<(), DecodeError> {
    if value.len() > L2TP_IFNAME_MAX_LEN {
        return Err(DecodeError::from(format!(
            "L2TP_ATTR_IFNAME too long: {} > {}",
            value.len(),
            L2TP_IFNAME_MAX_LEN
        )));
    }
    Ok(())
}

fn parse_cookie(payload: &[u8]) -> Result<Vec<u8>, DecodeError> {
    validate_cookie_len(payload, "L2TP_ATTR_COOKIE")?;
    Ok(payload.to_vec())
}

fn parse_peer_cookie(payload: &[u8]) -> Result<Vec<u8>, DecodeError> {
    validate_cookie_len(payload, "L2TP_ATTR_PEER_COOKIE")?;
    Ok(payload.to_vec())
}

fn validate_cookie_len(payload: &[u8], name: &str) -> Result<(), DecodeError> {
    match payload.len() {
        0 | 4 | 8 => Ok(()),
        n => Err(DecodeError::from(format!(
            "{name} has invalid length {n}: must be 0, 4, or 8 bytes",
        ))),
    }
}
