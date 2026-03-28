// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u16, Emitable, NlaBuffer, Parseable, ParseableParametrized,
};
use netlink_packet_generic::{GenlBuffer, GenlHeader};

use crate::{
    L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage, L2tpPwType,
    L2tpStatsAttr, L2TP_ATTR_COOKIE, L2TP_ATTR_IFNAME, L2TP_COOKIE_MAX_LEN,
    L2TP_IFNAME_MAX_LEN,
};

#[test]
fn test_tunnel_create_message_parse_emit() {
    // Captured format is generic-netlink header + payload attributes.
    let raw: Vec<u8> = vec![
        0x01, 0x01, 0x00,
        0x00, // genl header: cmd tunnel_create, version 1
        0x08, 0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, // CONN_ID=1
        0x08, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, // PEER_CONN_ID=2
        0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00, // PROTO_VERSION=3
        0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ENCAP_TYPE=UDP
        0x08, 0x00, 0x17, 0x00, 0x09, 0x00, 0x00, 0x00, // FD=9
    ];

    let expected = L2tpMessage::tunnel_create(vec![
        L2tpAttribute::ConnId(1),
        L2tpAttribute::PeerConnId(2),
        L2tpAttribute::ProtoVersion(3),
        L2tpAttribute::EncapType(L2tpEncapType::Udp),
        L2tpAttribute::Fd(9),
    ]);

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();
    assert_eq!(header.cmd, 1);
    assert_eq!(header.version, 1);

    let parsed =
        L2tpMessage::parse_with_param(&raw[header.buffer_len()..], header)
            .unwrap();
    assert_eq!(expected, parsed);

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[header.buffer_len()..]);
    assert_eq!(buffer, raw);
}

#[test]
fn test_attr_nested_stats_emit_parse() {
    let attr = L2tpAttribute::Stats(vec![
        L2tpStatsAttr::TxPackets(42),
        L2tpStatsAttr::RxErrors(1),
    ]);
    let mut raw = vec![0u8; attr.buffer_len()];
    attr.emit(&mut raw);

    let nla = NlaBuffer::new_checked(&raw).unwrap();
    let parsed = L2tpAttribute::parse(&nla).unwrap();
    assert_eq!(attr, parsed);
}

#[test]
fn test_cookie_constructor_len_check() {
    assert!(L2tpAttribute::cookie(vec![]).is_ok());
    assert!(L2tpAttribute::cookie(vec![0u8; 4]).is_ok());
    assert!(L2tpAttribute::cookie(vec![0u8; 8]).is_ok());
    assert!(L2tpAttribute::cookie(vec![0u8; 1]).is_err());
    assert!(L2tpAttribute::cookie(vec![0u8; 3]).is_err());
    assert!(L2tpAttribute::cookie(vec![0u8; 5]).is_err());
    assert!(L2tpAttribute::cookie(vec![0u8; 7]).is_err());
    assert!(L2tpAttribute::cookie(vec![0u8; L2TP_COOKIE_MAX_LEN + 1]).is_err());
}

#[test]
fn test_ifname_constructor_len_check() {
    assert!(L2tpAttribute::if_name("x".repeat(L2TP_IFNAME_MAX_LEN)).is_ok());
    assert!(
        L2tpAttribute::if_name("x".repeat(L2TP_IFNAME_MAX_LEN + 1)).is_err()
    );
}

#[test]
fn test_invalid_cookie_parse_error() {
    let raw = emit_nla(L2TP_ATTR_COOKIE, &[0u8; L2TP_COOKIE_MAX_LEN + 1]);
    let nla = NlaBuffer::new_checked(&raw).unwrap();
    assert!(L2tpAttribute::parse(&nla).is_err());
}

#[test]
fn test_invalid_ifname_parse_error() {
    let raw = emit_nla(L2TP_ATTR_IFNAME, &[b'x'; L2TP_IFNAME_MAX_LEN + 1]);
    let nla = NlaBuffer::new_checked(&raw).unwrap();
    assert!(L2tpAttribute::parse(&nla).is_err());
}

#[test]
fn test_message_command_constructors() {
    assert_eq!(L2tpMessage::tunnel_get(vec![]).cmd, L2tpCmd::TunnelGet);
    assert_eq!(
        L2tpMessage::session_create(vec![L2tpAttribute::PwType(
            L2tpPwType::Ppp,
        )])
        .cmd,
        L2tpCmd::SessionCreate
    );
}

fn emit_nla(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let aligned_len = (len + 3) & !3;
    let mut raw = vec![0u8; aligned_len];
    emit_u16(&mut raw[0..2], len as u16).unwrap();
    emit_u16(&mut raw[2..4], kind).unwrap();
    raw[4..(4 + value.len())].copy_from_slice(value);
    raw
}
