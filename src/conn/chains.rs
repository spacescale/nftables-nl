//! Chain operations and their Netfilter Netlink encoding.

use super::{ConnError, Transport};
use crate::chain::{Chain, ChainHook};
use crate::types::{NfGenMsg, NftMessage, NftMsgType};
use crate::{Batch, TableFamily};
use netlink_packet_core::{
    DefaultNla, Emitable, NLA_F_NESTED, NLM_F_CREATE, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};

// Attribute identifiers from the Linux nftables UAPI:
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

// Attribute identifiers nested inside NFTA_CHAIN_HOOK.
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_HOOK_DEV: u16 = 3;

#[allow(private_bounds)]
impl<'a, T: Transport> Batch<'a, T> {
    /// Queues a chain addition for the next batch commit.
    ///
    /// Uses the table name and family from `chain.table`. Other table fields are
    /// ignored. This method does not create the table implicitly.
    ///
    /// Regular chains omit the hook, priority, type, policy, and device. Base
    /// chains supply a hook, priority, and type together, with an optional policy
    /// and a device where supported. An omitted base-chain policy defaults to
    /// accept. Existing chains retain their rules; the kernel may reject
    /// incompatible changes to their configuration.
    ///
    /// The table must already exist or be queued earlier in this batch.
    /// Call [`commit`](Self::commit) to send the transaction and check kernel replies.
    ///
    /// # Errors
    ///
    /// Returns [`ConnError::InvalidChain`] for empty names, names longer than
    /// 255 bytes, embedded zero bytes, an unspecified family, incomplete base-chain
    /// options, or policy/device options on regular chains. Device names must be
    /// 1 to 15 bytes without embedded zeros. Devices are only supported for NETDEV
    /// base chains and INET ingress base chains.
    ///
    /// Validation errors leave the batch unchanged. Transport and kernel errors,
    /// including missing tables and unsupported configurations, are reported by
    /// [`commit`](Self::commit).
    ///
    /// # Examples
    ///
    /// Create a dormant table and a regular chain in one transaction:
    ///
    /// ```no_run
    /// use nftables_nl::chain::Chain;
    /// use nftables_nl::{Conn, ConnError, Table, TableFamily, TableFlags};
    ///
    /// let mut conn = Conn::new()?;
    /// let table = Table {
    ///     name: "filter".into(),
    ///     family: TableFamily::INET,
    ///     flags: TableFlags::DORMANT,
    ///     use_count: 0,
    ///     owner: None,
    /// };
    /// let chain = Chain {
    ///     name: "services".into(),
    ///     table: table.clone(),
    ///     hooknum: None,
    ///     priority: None,
    ///     chain_type: None,
    ///     policy: None,
    ///     device: None,
    /// };
    ///
    /// let mut batch = conn.batch();
    /// batch.add_table(&table)?;
    /// batch.add_chain(&chain)?;
    /// batch.commit()?;
    /// # Ok::<(), ConnError>(())
    /// ```
    ///
    /// # References
    ///
    /// - [nftables NEWCHAIN request](https://docs.kernel.org/netlink/specs/nftables.html#newchain)
    /// - [Chain attributes](https://docs.kernel.org/netlink/specs/nftables.html#chain-attrs)
    pub fn add_chain(&mut self, chain: &Chain) -> Result<(), ConnError> {
        // Reject invalid options  before modifying the batch
        validate_chain(chain)?;

        // Prepare the attributes describing this chain.
        let attributes = chain_attributes(chain);

        // The family belongs in the four-byte Netfilter header.
        let nfgen = NfGenMsg {
            nfgen_family: chain.table.family.as_raw(),
            version: 0,
            res_id: 0,
        };

        let mut data = nfgen.encode().to_vec();

        let start = data.len();
        data.resize(start + attributes.as_slice().buffer_len(), 0);
        // Encode the attributes into the reserved space.
        attributes.as_slice().emit(&mut data[start..]);

        let payload = NftMessage {
            message_type: NftMsgType::NEW_CHAIN.header_type(),
            data,
        };

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_CREATE;

        let message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(payload));

        self.push(message);
        Ok(())
    }
}

/// Validates chain creation options before anything is queued.
fn validate_chain(chain: &Chain) -> Result<(), ConnError> {
    // Both names must fit their kernel attributes, including a final zero
    // Kernel definitions:
    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h
    for name in [&chain.name, &chain.table.name] {
        if name.is_empty() || name.len() >= 256 {
            return Err(ConnError::InvalidChain(
                "chain and table names must contain between 1 and 255 bytes",
            ));
        }

        if name.as_bytes().contains(&0) {
            return Err(ConnError::InvalidChain(
                "chain and table names must not contain a zero byte",
            ));
        }
    }

    if chain.table.family == TableFamily::UNSPEC {
        return Err(ConnError::InvalidChain("a concrete table family is required"));
    }

    match (chain.hooknum, chain.priority, chain.chain_type) {
        (None, None, None) => {
            if chain.policy.is_some() || chain.device.is_some() {
                return Err(ConnError::InvalidChain(
                    "regular chains must not specify a policy or device",
                ));
            }
        }
        // A base chain supplies all three.
        (Some(_), Some(_), Some(_)) => {}

        // Reject incomplete combinations.
        _ => {
            return Err(ConnError::InvalidChain(
                "base chains require a hook, priority, and chain type together",
            ));
        }
    }

    if let Some(device) = &chain.device {
        // Linux interface names allow 15 bytes plus a terminating zero.
        if device.is_empty() || device.len() > 15 {
            return Err(ConnError::InvalidChain(
                "device name must contain between 1 and 15 bytes",
            ));
        }

        if device.as_bytes().contains(&0) {
            return Err(ConnError::InvalidChain("device name must not contain a zero byte"));
        }

        // Devices apply to NETDEV chains and INET ingress chains.
        let is_netdev = chain.table.family == TableFamily::NETDEV;
        let is_inet_ingress = chain.table.family == TableFamily::INET && chain.hooknum == Some(ChainHook::INET_INGRESS);

        if !is_netdev && !is_inet_ingress {
            return Err(ConnError::InvalidChain(
                "a device is only supported for NETDEV chains or INET ingress chains",
            ));
        }
    }

    Ok(())
}

/// Converts a string into bytes with a terminating zero.
fn nul_terminated(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

/// Builds the attributes describing a regular or base chain.
///
/// Attribute definitions:
/// <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h>
fn chain_attributes(chain: &Chain) -> Vec<DefaultNla> {
    let mut attributes = vec![
        // NFTA_CHAIN_TABLE = 1: the existing table's name.
        DefaultNla::new(NFTA_CHAIN_TABLE, nul_terminated(&chain.table.name)),
        // NFTA_CHAIN_NAME = 3: the chain's name.
        DefaultNla::new(NFTA_CHAIN_NAME, nul_terminated(&chain.name)),
    ];

    // Validation ensures these three are either all present or all absent.
    if let (Some(hook), Some(priority), Some(chain_type)) = (chain.hooknum, chain.priority, chain.chain_type) {
        let mut hook_attributes = vec![
            // NFTA_HOOK_HOOKNUM = 1.
            DefaultNla::new(NFTA_HOOK_HOOKNUM, hook.as_raw().to_be_bytes().to_vec()),
            // NFTA_HOOK_PRIORITY = 2, preserving signed priorities.
            DefaultNla::new(NFTA_HOOK_PRIORITY, priority.as_raw().to_be_bytes().to_vec()),
        ];

        if let Some(device) = &chain.device {
            // NFTA_HOOK_DEV = 3: the network interface name.
            hook_attributes.push(DefaultNla::new(NFTA_HOOK_DEV, nul_terminated(device)));
        }

        // Encode the inner attributes into their own buffer.
        let mut hook_data = vec![0; hook_attributes.as_slice().buffer_len()];
        hook_attributes.as_slice().emit(&mut hook_data);

        // NFTA_CHAIN_HOOK = 4.
        // NLA_F_NESTED marks its contents as more attributes.
        attributes.push(DefaultNla::new(NFTA_CHAIN_HOOK | NLA_F_NESTED, hook_data));

        // NFTA_CHAIN_TYPE = 7: "filter", "route", or "nat".
        attributes.push(DefaultNla::new(NFTA_CHAIN_TYPE, nul_terminated(chain_type.as_str())));
    }

    if let Some(policy) = chain.policy {
        // NFTA_CHAIN_POLICY = 5: accept or drop, in network byte order.
        attributes.push(DefaultNla::new(
            NFTA_CHAIN_POLICY,
            policy.as_raw().to_be_bytes().to_vec(),
        ));
    }

    attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainPolicy, ChainPriority, ChainType};
    use crate::netlink::decode_messages;
    use crate::{Table, TableFlags};
    use netlink_sys::SocketAddr;
    use std::collections::VecDeque;
    use std::io;

    #[derive(Default)]
    struct FakeTransport {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
    }

    impl Transport for FakeTransport {
        fn send_request(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.sent.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn receive_reply(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
            let bytes = self
                .replies
                .pop_front()
                .ok_or_else(|| io::Error::other("no prepared acknowledgement"))?;
            Ok((bytes, SocketAddr::new(0, 0)))
        }
    }

    impl FakeTransport {
        fn with_acknowledgements(sequences: &[u32]) -> Self {
            let replies = sequences
                .iter()
                .map(|sequence| {
                    // Independently construct a successful NLMSG_ERROR reply.
                    let mut bytes = 36u32.to_ne_bytes().to_vec();
                    bytes.extend_from_slice(&2u16.to_ne_bytes());
                    bytes.extend_from_slice(&0u16.to_ne_bytes());
                    bytes.extend_from_slice(&sequence.to_ne_bytes());
                    bytes.extend_from_slice(&0u32.to_ne_bytes());
                    bytes.extend_from_slice(&0i32.to_ne_bytes());
                    // Original request header carried by the acknowledgement.
                    bytes.extend_from_slice(&16u32.to_ne_bytes());
                    bytes.extend_from_slice(&[0; 12]);
                    bytes
                })
                .collect();
            Self {
                replies,
                ..Self::default()
            }
        }
    }

    fn regular_chain() -> Chain {
        Chain {
            name: "input".into(),
            table: Table {
                name: "filter".into(),
                family: TableFamily::INET,
                flags: TableFlags::DORMANT,
                use_count: 0,
                owner: None,
            },
            hooknum: None,
            priority: None,
            chain_type: None,
            policy: None,
            device: None,
        }
    }

    fn base_chain() -> Chain {
        Chain {
            hooknum: Some(ChainHook::INPUT),
            priority: Some(ChainPriority::FILTER),
            chain_type: Some(ChainType::FILTER),
            ..regular_chain()
        }
    }

    // Build expected wire bytes independently of DefaultNla and emit.
    // Attribute headers use native byte order; length excludes padding.
    fn attribute_bytes(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = Vec::new();
        let Ok(length_field) = u16::try_from(length) else {
            panic!("test attribute is too large");
        };
        bytes.extend_from_slice(&length_field.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(length.next_multiple_of(4), 0);
        bytes
    }

    #[test]
    fn add_chain_queues_regular_chain_with_correct_message_and_family() {
        let mut conn = super::super::Conn {
            transport: FakeTransport::with_acknowledgements(&[2]),
            sequence: 0,
        };
        let mut chain = regular_chain();
        chain.table.family = TableFamily::IPV6;

        let mut batch = conn.batch();
        assert!(batch.add_chain(&chain).is_ok());
        assert!(batch.commit().is_ok());

        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid serialized batch");
        };
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].header.message_type, 0x10); // BEGIN.
        assert_eq!(messages[2].header.message_type, 0x11); // END.
        let message = &messages[1];
        assert_eq!(message.header.message_type, 0x0a03); // NEW_CHAIN.
        assert_eq!(message.header.flags, 0x0405); // REQUEST | CREATE | ACK, no EXCL.
        assert_eq!(message.header.sequence_number, 2);

        let NetlinkPayload::InnerMessage(payload) = &message.payload else {
            panic!("expected an nftables payload");
        };
        let mut expected = vec![10, 0, 0, 0]; // IPv6 nfgenmsg.
        expected.extend(attribute_bytes(1, b"filter\0"));
        expected.extend(attribute_bytes(3, b"input\0"));
        assert_eq!(payload.data, expected);
        assert_eq!(message.header.length as usize, 16 + expected.len());
    }

    #[test]
    fn add_chain_queues_base_chain_with_device_priority_type_and_policy() {
        let mut conn = super::super::Conn {
            transport: FakeTransport::with_acknowledgements(&[2]),
            sequence: 0,
        };
        let mut chain = base_chain();
        chain.hooknum = Some(ChainHook::INET_INGRESS);
        chain.priority = Some(ChainPriority::RAW);
        chain.device = Some("eth0".into());
        chain.policy = Some(ChainPolicy::DROP);

        let mut batch = conn.batch();
        assert!(batch.add_chain(&chain).is_ok());
        assert!(batch.commit().is_ok());

        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid serialized batch");
        };
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[1].header.message_type, 0x0a03);
        assert_eq!(messages[1].header.flags, 0x0405);

        let mut hook = attribute_bytes(1, &[0, 0, 0, 5]);
        hook.extend(attribute_bytes(2, &[0xff, 0xff, 0xfe, 0xd4])); // -300.
        hook.extend(attribute_bytes(3, b"eth0\0"));
        let mut expected = vec![1, 0, 0, 0]; // INET nfgenmsg.
        expected.extend(attribute_bytes(1, b"filter\0"));
        expected.extend(attribute_bytes(3, b"input\0"));
        expected.extend(attribute_bytes(0x8004, &hook));
        expected.extend(attribute_bytes(7, b"filter\0"));
        expected.extend(attribute_bytes(5, &[0, 0, 0, 0]));

        let NetlinkPayload::InnerMessage(payload) = &messages[1].payload else {
            panic!("expected an nftables payload");
        };
        assert_eq!(payload.data, expected);
        assert_eq!(messages[1].header.length as usize, 16 + expected.len());
    }

    #[test]
    fn add_chain_without_commit_sends_nothing_and_assigns_no_sequence() {
        let mut conn = super::super::Conn {
            transport: FakeTransport::default(),
            sequence: 41,
        };
        {
            let mut batch = conn.batch();
            assert!(batch.add_chain(&regular_chain()).is_ok());
            assert!(batch.add_chain(&base_chain()).is_ok());
        } // Drop both queued operations without committing.
        assert!(conn.transport.sent.is_empty());
        assert_eq!(conn.sequence, 41);
    }

    #[test]
    fn add_chain_rejects_invalid_input_without_queueing() {
        let invalid_chains = [
            Chain {
                name: String::new(),
                ..regular_chain()
            },
            Chain {
                name: "a".repeat(256),
                ..regular_chain()
            },
            Chain {
                name: "in\0put".into(),
                ..regular_chain()
            },
            Chain {
                table: Table {
                    family: TableFamily::UNSPEC,
                    ..regular_chain().table
                },
                ..regular_chain()
            },
            Chain {
                table: Table {
                    name: String::new(),
                    ..regular_chain().table
                },
                ..regular_chain()
            },
            Chain {
                hooknum: Some(ChainHook::INPUT),
                ..regular_chain()
            },
            Chain {
                policy: Some(ChainPolicy::DROP),
                ..regular_chain()
            },
            Chain {
                device: Some("eth0".into()),
                ..regular_chain()
            },
            Chain {
                device: Some("eth0".into()),
                ..base_chain()
            },
            Chain {
                hooknum: Some(ChainHook::INET_INGRESS),
                device: Some("a".repeat(16)),
                ..base_chain()
            },
            Chain {
                hooknum: Some(ChainHook::INET_INGRESS),
                device: Some(String::new()),
                ..base_chain()
            },
            Chain {
                hooknum: Some(ChainHook::INET_INGRESS),
                device: Some("et\0h0".into()),
                ..base_chain()
            },
        ];

        for chain in invalid_chains {
            let mut conn = super::super::Conn {
                transport: FakeTransport::default(),
                sequence: 0,
            };
            let mut batch = conn.batch();
            assert!(
                matches!(batch.add_chain(&chain), Err(ConnError::InvalidChain(_))),
                "chain {chain:?}"
            );
            // If validation accidentally queued anything, commit would send it.
            assert!(batch.commit().is_ok());
            assert!(conn.transport.sent.is_empty());
            assert_eq!(conn.sequence, 0);
        }
    }

    #[test]
    fn add_chain_invalid_input_preserves_previously_queued_operation() {
        let mut conn = super::super::Conn {
            transport: FakeTransport::with_acknowledgements(&[2]),
            sequence: 0,
        };
        let mut batch = conn.batch();
        assert!(batch.add_chain(&regular_chain()).is_ok());
        let invalid = Chain {
            name: String::new(),
            ..base_chain()
        };
        assert!(matches!(batch.add_chain(&invalid), Err(ConnError::InvalidChain(_))));
        assert!(batch.commit().is_ok());

        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid serialized batch");
        };
        assert_eq!(messages.len(), 3); // BEGIN + original operation + END.
        let NetlinkPayload::InnerMessage(payload) = &messages[1].payload else {
            panic!("expected an nftables payload");
        };
        let mut expected = vec![1, 0, 0, 0];
        expected.extend(attribute_bytes(1, b"filter\0"));
        expected.extend(attribute_bytes(3, b"input\0"));
        assert_eq!(payload.data, expected);
    }

    #[test]
    fn add_chain_preserves_queue_order_and_allows_repeated_additions() {
        let mut conn = super::super::Conn {
            transport: FakeTransport::with_acknowledgements(&[2, 3, 4]),
            sequence: 0,
        };
        let first = regular_chain();
        let second = Chain {
            name: "output".into(),
            ..regular_chain()
        };
        let mut batch = conn.batch();
        assert!(batch.add_chain(&first).is_ok());
        assert!(batch.add_chain(&second).is_ok());
        assert!(batch.add_chain(&first).is_ok());
        assert!(batch.commit().is_ok());

        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid serialized batch");
        };
        assert_eq!(messages.len(), 5); // BEGIN + three operations + END.
        for (message, name) in messages[1..4]
            .iter()
            .zip([b"input\0".as_slice(), b"output\0", b"input\0"])
        {
            assert_eq!(message.header.message_type, 0x0a03);
            assert_eq!(message.header.flags, 0x0405);
            let NetlinkPayload::InnerMessage(payload) = &message.payload else {
                panic!("expected an nftables payload");
            };
            let mut expected = vec![1, 0, 0, 0];
            expected.extend(attribute_bytes(1, b"filter\0"));
            expected.extend(attribute_bytes(3, name));
            assert_eq!(payload.data, expected);
        }
        for (message, sequence) in messages.iter().zip(1..=5) {
            assert_eq!(message.header.sequence_number, sequence);
        }
    }

    #[test]
    fn nul_terminated_empty_string_produces_one_zero() {
        assert_eq!(nul_terminated(""), vec![0]);
    }

    #[test]
    fn nul_terminated_ascii_preserves_bytes_and_appends_zero() {
        assert_eq!(nul_terminated("eth0"), vec![101, 116, 104, 48, 0]);
    }

    #[test]
    fn nul_terminated_unicode_preserves_utf8_bytes() {
        assert_eq!(nul_terminated("é"), vec![0xc3, 0xa9, 0]);
    }

    #[test]
    fn nul_terminated_preserves_existing_zeros_without_validating() {
        // Validation belongs to validate_chain, not this encoding helper.
        assert_eq!(nul_terminated("a\0b"), vec![97, 0, 98, 0]);
        assert_eq!(nul_terminated("a\0"), vec![97, 0, 0]);
    }

    #[test]
    fn chain_attributes_regular_chain_contains_only_table_and_name() {
        assert_eq!(
            chain_attributes(&regular_chain()),
            vec![
                DefaultNla::new(1, b"filter\0".to_vec()),
                DefaultNla::new(3, b"input\0".to_vec()),
            ],
        );
    }

    #[test]
    fn chain_attributes_regular_chain_emits_headers_terminators_and_padding() {
        let attributes = chain_attributes(&regular_chain());
        let mut actual = vec![0xff; attributes.as_slice().buffer_len()];
        attributes.as_slice().emit(&mut actual);

        let mut expected = attribute_bytes(1, b"filter\0");
        expected.extend(attribute_bytes(3, b"input\0"));
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 24);
    }

    #[test]
    fn chain_attributes_base_chain_encodes_nested_hook_and_signed_priorities() {
        for (priority, expected_bytes) in [
            (ChainPriority::FIRST, [0x80, 0, 0, 0]),
            (ChainPriority::RAW, [0xff, 0xff, 0xfe, 0xd4]),
            (ChainPriority::FILTER, [0, 0, 0, 0]),
            (ChainPriority::SECURITY, [0, 0, 0, 50]),
            (ChainPriority::LAST, [0x7f, 0xff, 0xff, 0xff]),
        ] {
            let chain = Chain {
                priority: Some(priority),
                ..base_chain()
            };
            // Literal identifiers and flag verify the production constants too.
            let mut hook = attribute_bytes(1, &[0, 0, 0, 1]);
            hook.extend(attribute_bytes(2, &expected_bytes));

            assert_eq!(
                chain_attributes(&chain),
                vec![
                    DefaultNla::new(1, b"filter\0".to_vec()),
                    DefaultNla::new(3, b"input\0".to_vec()),
                    DefaultNla::new(0x8004, hook),
                    DefaultNla::new(7, b"filter\0".to_vec()),
                ],
                "priority {priority:?}",
            );
        }
    }

    #[test]
    fn chain_attributes_base_chain_encodes_all_chain_types() {
        for (chain_type, expected_name) in [
            (ChainType::FILTER, b"filter\0".as_slice()),
            (ChainType::ROUTE, b"route\0".as_slice()),
            (ChainType::NAT, b"nat\0".as_slice()),
        ] {
            let chain = Chain {
                chain_type: Some(chain_type),
                ..base_chain()
            };
            let attributes = chain_attributes(&chain);
            assert_eq!(attributes.len(), 4);
            assert_eq!(attributes[3], DefaultNla::new(7, expected_name.to_vec()));
        }
    }

    #[test]
    fn chain_attributes_base_chain_encodes_optional_policy() {
        for (policy, expected_value) in [(ChainPolicy::DROP, 0), (ChainPolicy::ACCEPT, 1)] {
            let chain = Chain {
                policy: Some(policy),
                ..base_chain()
            };
            let attributes = chain_attributes(&chain);
            assert_eq!(attributes.len(), 5);
            assert_eq!(attributes[4], DefaultNla::new(5, vec![0, 0, 0, expected_value]));
        }
    }

    #[test]
    fn chain_attributes_base_chain_nests_device_with_hook_and_priority() {
        for (family, hooknum, hook_value) in [
            (TableFamily::NETDEV, ChainHook::INGRESS, 0),
            (TableFamily::NETDEV, ChainHook::EGRESS, 1),
            (TableFamily::INET, ChainHook::INET_INGRESS, 5),
        ] {
            let mut chain = base_chain();
            chain.table.family = family;
            chain.hooknum = Some(hooknum);
            chain.device = Some("eth0".into());
            chain.policy = Some(ChainPolicy::DROP);

            let mut hook = attribute_bytes(1, &[0, 0, 0, hook_value]);
            hook.extend(attribute_bytes(2, &[0, 0, 0, 0]));
            hook.extend(attribute_bytes(3, b"eth0\0"));
            let attributes = chain_attributes(&chain);
            assert_eq!(attributes.len(), 5);
            assert_eq!(attributes[2], DefaultNla::new(0x8004, hook));
            assert_eq!(attributes[4], DefaultNla::new(5, vec![0, 0, 0, 0]));
        }
    }

    #[test]
    fn chain_attributes_ignores_table_state_and_preserves_unicode_names() {
        let mut chain = regular_chain();
        chain.name = "entrée".into();
        chain.table.name = "réseau".into();
        chain.table.flags = TableFlags::OWNER | TableFlags::PERSIST;
        chain.table.use_count = 42;
        chain.table.owner = Some(123);

        assert_eq!(
            chain_attributes(&chain),
            vec![
                DefaultNla::new(1, b"r\xc3\xa9seau\0".to_vec()),
                DefaultNla::new(3, b"entr\xc3\xa9e\0".to_vec()),
            ],
        );
    }

    #[test]
    fn validate_chain_accepts_regular_chain_and_concrete_families() {
        for family in [
            TableFamily::INET,
            TableFamily::IPV4,
            TableFamily::IPV6,
            TableFamily::ARP,
            TableFamily::BRIDGE,
            TableFamily::NETDEV,
        ] {
            let mut chain = regular_chain();
            chain.table.family = family;
            assert!(validate_chain(&chain).is_ok(), "family {family:?}");
        }
    }

    #[test]
    fn validate_chain_accepts_name_length_boundaries_in_bytes() {
        for name in ["a".into(), "a".repeat(255), "é".repeat(127) + "a"] {
            let mut chain = regular_chain();
            chain.name.clone_from(&name);
            chain.table.name = name;
            assert!(validate_chain(&chain).is_ok());
        }
    }

    #[test]
    fn validate_chain_rejects_invalid_chain_and_table_names() {
        for name in [
            String::new(),
            "a".repeat(256),
            "a".repeat(257),
            "é".repeat(128),
            "\0name".into(),
            "na\0me".into(),
            "name\0".into(),
        ] {
            for is_table_name in [false, true] {
                let mut chain = regular_chain();
                if is_table_name {
                    chain.table.name.clone_from(&name);
                } else {
                    chain.name.clone_from(&name);
                }
                assert!(
                    matches!(validate_chain(&chain), Err(ConnError::InvalidChain(_))),
                    "name {name:?}, is_table_name {is_table_name}",
                );
            }
        }
    }

    #[test]
    fn validate_chain_rejects_unspecified_family() {
        for mut chain in [regular_chain(), base_chain()] {
            chain.table.family = TableFamily::UNSPEC;
            assert!(matches!(validate_chain(&chain), Err(ConnError::InvalidChain(_))));
        }
    }

    #[test]
    fn validate_chain_checks_every_hook_priority_and_type_presence_combination() {
        for hook_present in [false, true] {
            for priority_present in [false, true] {
                for type_present in [false, true] {
                    let chain = Chain {
                        hooknum: hook_present.then_some(ChainHook::INPUT),
                        priority: priority_present.then_some(ChainPriority::FILTER),
                        chain_type: type_present.then_some(ChainType::FILTER),
                        ..regular_chain()
                    };
                    let result = validate_chain(&chain);
                    let complete = hook_present && priority_present && type_present;
                    let absent = !hook_present && !priority_present && !type_present;
                    if complete || absent {
                        assert!(result.is_ok(), "chain {chain:?}");
                    } else {
                        assert!(matches!(result, Err(ConnError::InvalidChain(_))), "chain {chain:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn validate_chain_rejects_policy_or_device_on_regular_chain() {
        for (policy, device) in [
            (Some(ChainPolicy::ACCEPT), None),
            (Some(ChainPolicy::DROP), None),
            (None, Some("eth0".into())),
            (Some(ChainPolicy::DROP), Some("eth0".into())),
        ] {
            let chain = Chain {
                policy,
                device,
                ..regular_chain()
            };
            assert!(matches!(validate_chain(&chain), Err(ConnError::InvalidChain(_))));
        }
    }

    #[test]
    fn validate_chain_accepts_base_chain_with_optional_policy() {
        for policy in [None, Some(ChainPolicy::ACCEPT), Some(ChainPolicy::DROP)] {
            let chain = Chain { policy, ..base_chain() };
            assert!(validate_chain(&chain).is_ok());
        }
    }

    #[test]
    fn validate_chain_accepts_devices_on_netdev_and_inet_ingress() {
        for (family, hook) in [
            (TableFamily::NETDEV, ChainHook::INGRESS),
            (TableFamily::NETDEV, ChainHook::EGRESS),
            (TableFamily::INET, ChainHook::INET_INGRESS),
        ] {
            for device in [
                None,
                Some("eth0".into()),
                Some("a".repeat(15)),
                Some("é".repeat(7) + "a"),
            ] {
                let mut chain = base_chain();
                chain.table.family = family;
                chain.hooknum = Some(hook);
                chain.device = device;
                assert!(validate_chain(&chain).is_ok(), "chain {chain:?}");
            }
        }
    }

    #[test]
    fn validate_chain_rejects_invalid_device_names() {
        for device in [
            String::new(),
            "a".repeat(16),
            "a".repeat(17),
            "é".repeat(8),
            "\0eth0".into(),
            "et\0h0".into(),
            "eth0\0".into(),
        ] {
            let mut chain = base_chain();
            chain.table.family = TableFamily::NETDEV;
            chain.hooknum = Some(ChainHook::INGRESS);
            chain.device = Some(device);
            assert!(matches!(validate_chain(&chain), Err(ConnError::InvalidChain(_))));
        }
    }

    #[test]
    fn validate_chain_rejects_devices_on_other_hooks_and_families() {
        for family in [
            TableFamily::INET,
            TableFamily::IPV4,
            TableFamily::IPV6,
            TableFamily::BRIDGE,
        ] {
            for hook in [
                ChainHook::PRE_ROUTING,
                ChainHook::INPUT,
                ChainHook::FORWARD,
                ChainHook::OUTPUT,
                ChainHook::POST_ROUTING,
            ] {
                let mut chain = base_chain();
                chain.table.family = family;
                chain.hooknum = Some(hook);
                chain.device = Some("eth0".into());
                assert!(matches!(validate_chain(&chain), Err(ConnError::InvalidChain(_))));
            }
        }
        let mut chain = base_chain();
        chain.table.family = TableFamily::ARP;
        chain.device = Some("eth0".into());
        assert!(matches!(validate_chain(&chain), Err(ConnError::InvalidChain(_))));
    }
}
