// SPDX-License-Identifier: MIT

//! L2TP generic netlink constants from `include/uapi/linux/l2tp.h`.

pub const L2TP_GENL_NAME: &str = "l2tp";
pub const L2TP_GENL_VERSION: u8 = 0x1;
pub const L2TP_GENL_MCGROUP: &str = "l2tp";

pub const L2TP_CMD_NOOP: u8 = 0;
pub const L2TP_CMD_TUNNEL_CREATE: u8 = 1;
pub const L2TP_CMD_TUNNEL_DELETE: u8 = 2;
pub const L2TP_CMD_TUNNEL_MODIFY: u8 = 3;
pub const L2TP_CMD_TUNNEL_GET: u8 = 4;
pub const L2TP_CMD_SESSION_CREATE: u8 = 5;
pub const L2TP_CMD_SESSION_DELETE: u8 = 6;
pub const L2TP_CMD_SESSION_MODIFY: u8 = 7;
pub const L2TP_CMD_SESSION_GET: u8 = 8;

pub const L2TP_ATTR_NONE: u16 = 0;
pub const L2TP_ATTR_PW_TYPE: u16 = 1;
pub const L2TP_ATTR_ENCAP_TYPE: u16 = 2;
pub const L2TP_ATTR_OFFSET: u16 = 3;
pub const L2TP_ATTR_DATA_SEQ: u16 = 4;
pub const L2TP_ATTR_L2SPEC_TYPE: u16 = 5;
pub const L2TP_ATTR_L2SPEC_LEN: u16 = 6;
pub const L2TP_ATTR_PROTO_VERSION: u16 = 7;
pub const L2TP_ATTR_IFNAME: u16 = 8;
pub const L2TP_ATTR_CONN_ID: u16 = 9;
pub const L2TP_ATTR_PEER_CONN_ID: u16 = 10;
pub const L2TP_ATTR_SESSION_ID: u16 = 11;
pub const L2TP_ATTR_PEER_SESSION_ID: u16 = 12;
pub const L2TP_ATTR_UDP_CSUM: u16 = 13;
pub const L2TP_ATTR_VLAN_ID: u16 = 14;
pub const L2TP_ATTR_COOKIE: u16 = 15;
pub const L2TP_ATTR_PEER_COOKIE: u16 = 16;
pub const L2TP_ATTR_DEBUG: u16 = 17;
pub const L2TP_ATTR_RECV_SEQ: u16 = 18;
pub const L2TP_ATTR_SEND_SEQ: u16 = 19;
pub const L2TP_ATTR_LNS_MODE: u16 = 20;
pub const L2TP_ATTR_USING_IPSEC: u16 = 21;
pub const L2TP_ATTR_RECV_TIMEOUT: u16 = 22;
pub const L2TP_ATTR_FD: u16 = 23;
pub const L2TP_ATTR_IP_SADDR: u16 = 24;
pub const L2TP_ATTR_IP_DADDR: u16 = 25;
pub const L2TP_ATTR_UDP_SPORT: u16 = 26;
pub const L2TP_ATTR_UDP_DPORT: u16 = 27;
pub const L2TP_ATTR_MTU: u16 = 28;
pub const L2TP_ATTR_MRU: u16 = 29;
pub const L2TP_ATTR_STATS: u16 = 30;
pub const L2TP_ATTR_IP6_SADDR: u16 = 31;
pub const L2TP_ATTR_IP6_DADDR: u16 = 32;
pub const L2TP_ATTR_UDP_ZERO_CSUM6_TX: u16 = 33;
pub const L2TP_ATTR_UDP_ZERO_CSUM6_RX: u16 = 34;
pub const L2TP_ATTR_PAD: u16 = 35;

pub const L2TP_ATTR_STATS_NONE: u16 = 0;
pub const L2TP_ATTR_TX_PACKETS: u16 = 1;
pub const L2TP_ATTR_TX_BYTES: u16 = 2;
pub const L2TP_ATTR_TX_ERRORS: u16 = 3;
pub const L2TP_ATTR_RX_PACKETS: u16 = 4;
pub const L2TP_ATTR_RX_BYTES: u16 = 5;
pub const L2TP_ATTR_RX_SEQ_DISCARDS: u16 = 6;
pub const L2TP_ATTR_RX_OOS_PACKETS: u16 = 7;
pub const L2TP_ATTR_RX_ERRORS: u16 = 8;
pub const L2TP_ATTR_STATS_PAD: u16 = 9;
pub const L2TP_ATTR_RX_COOKIE_DISCARDS: u16 = 10;
pub const L2TP_ATTR_RX_INVALID: u16 = 11;

pub const L2TP_PWTYPE_NONE: u16 = 0x0000;
pub const L2TP_PWTYPE_ETH_VLAN: u16 = 0x0004;
pub const L2TP_PWTYPE_ETH: u16 = 0x0005;
pub const L2TP_PWTYPE_PPP: u16 = 0x0007;
pub const L2TP_PWTYPE_PPP_AC: u16 = 0x0008;
pub const L2TP_PWTYPE_IP: u16 = 0x000b;

pub const L2TP_L2SPECTYPE_NONE: u8 = 0;
pub const L2TP_L2SPECTYPE_DEFAULT: u8 = 1;

pub const L2TP_ENCAPTYPE_UDP: u16 = 0;
pub const L2TP_ENCAPTYPE_IP: u16 = 1;
