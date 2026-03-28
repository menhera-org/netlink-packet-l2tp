# netlink-packet-l2tp

Rust crate providing Linux L2TP Generic Netlink packet definitions.

This crate follows the `netlink-packet-*` style:

- `L2tpMessage` as the Generic Netlink family payload (`family_name = "l2tp"`).
- `L2tpCmd` for L2TP command IDs.
- `L2tpAttribute` and `L2tpStatsAttr` for netlink attributes.

The definitions are based on Linux UAPI `include/uapi/linux/l2tp.h`.
