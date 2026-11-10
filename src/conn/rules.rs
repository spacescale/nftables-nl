//! Rule creation and expression encoding.
//!
//! Kernel definitions:
//! <https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h>
//!

use super::{ConnError, Transport, encode_attributes, nul_terminated};
use crate::rule::{Expression, Rule, Verdict};
use crate::types::{NfGenMsg, NftMessage, NftMsgType};
use crate::{Batch, TableFamily};
use netlink_packet_core::{
    DefaultNla, NLA_F_NESTED, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};

// An entry inside an nftables expression list.
// Each expression uses this same identifier; it is not an array index.
const NFTA_LIST_ELEM: u16 = 1;

// Inside an expression: its null-terminated name, such as "counter".
const NFTA_EXPR_NAME: u16 = 1;

// Inside an expression: nested attributes configuring that expression.
const NFTA_EXPR_DATA: u16 = 2;

// Fields inside an immediate expression.
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

// Inside immediate data: a nested verdict.
const NFTA_DATA_VERDICT: u16 = 2;

// Inside the verdict: its numeric code.
const NFTA_VERDICT_CODE: u16 = 1;

// The register used for packet-processing decisions.
const NFT_REG_VERDICT: u32 = 0;

// Linux Netfilter verdict codes.
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;

#[allow(private_bounds)]
impl<'a, T: Transport> Batch<'a, T> {
    /// Queues a rule at the end of its chain without sending it.
    ///
    /// The table and chain must exist or be queued earlier in this batch.
    /// Only their names and family are used; other chain settings are ignored.
    /// The rule is encoded immediately, so the batch does not retain its borrow.
    /// Call [`commit`](Self::commit) to apply the transaction.
    ///
    /// Returns [`ConnError::InvalidRule`] for invalid parent names or an
    /// unspecified family, leaving the batch unchanged. Kernel and transport
    /// errors are reported by `commit`. Repeated calls append separate rules.
    ///
    /// # Examples
    ///
    /// Append a counter and accept verdict to an existing chain:
    ///
    /// ```no_run
    /// use nftables_nl::chain::Chain;
    /// use nftables_nl::rule::{Rule, Verdict};
    /// use nftables_nl::{Conn, ConnError};
    ///
    /// fn append_accept(conn: &mut Conn, chain: &Chain) -> Result<(), ConnError> {
    ///     let rule = Rule::new(chain).counter().verdict(Verdict::Accept);
    ///     let mut batch = conn.batch();
    ///     batch.add_rule(&rule)?;
    ///     batch.commit()
    /// }
    /// ```
    ///
    /// See the [kernel rule API](https://docs.kernel.org/netlink/specs/nftables.html#newrule).
    pub fn add_rule(&mut self, rule: &Rule<'_>) -> Result<(), ConnError> {
        validate_rule(rule)?;

        let nfgen = NfGenMsg {
            nfgen_family: rule.chain.table.family.as_raw(),
            version: 0,
            res_id: 0,
        };
        let mut data = nfgen.encode().to_vec();
        data.extend_from_slice(&encode_attributes(&rule_attributes(rule)));

        let payload = NftMessage {
            message_type: NftMsgType::NEW_RULE.header_type(),
            data,
        };
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND;

        self.push(NetlinkMessage::new(header, NetlinkPayload::InnerMessage(payload)));
        Ok(())
    }
}

/// Validates the parent names and family before queueing a rule.
fn validate_rule(rule: &Rule<'_>) -> Result<(), ConnError> {
    for name in [&rule.chain.table.name, &rule.chain.name] {
        if name.is_empty() || name.len() >= 256 {
            return Err(ConnError::InvalidRule(
                "table and chain names must contain between 1 and 255 bytes",
            ));
        }

        if name.as_bytes().contains(&0) {
            return Err(ConnError::InvalidRule(
                "table and chain names must not contain a zero byte",
            ));
        }
    }

    if rule.chain.table.family == TableFamily::UNSPEC {
        return Err(ConnError::InvalidRule("a concrete table family is required"));
    }

    Ok(())
}

/// Builds a counter expression with counters initially set to zero.
fn counter_expression() -> DefaultNla {
    let attributes = [
        DefaultNla::new(NFTA_EXPR_NAME, nul_terminated("counter")),
        DefaultNla::new(NFTA_EXPR_DATA | NLA_F_NESTED, Vec::new()),
    ];

    DefaultNla::new(NFTA_LIST_ELEM | NLA_F_NESTED, encode_attributes(&attributes))
}

/// Builds an immediate expression targeting the verdict register.
fn verdict_expression(verdict: &Verdict) -> DefaultNla {
    let code = match verdict {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
    };

    let verdict_attributes = [DefaultNla::new(NFTA_VERDICT_CODE, code.to_be_bytes().to_vec())];

    let data_attributes = [DefaultNla::new(
        NFTA_DATA_VERDICT | NLA_F_NESTED,
        encode_attributes(&verdict_attributes),
    )];

    let immediate_attributes = [
        DefaultNla::new(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT.to_be_bytes().to_vec()),
        DefaultNla::new(NFTA_IMMEDIATE_DATA | NLA_F_NESTED, encode_attributes(&data_attributes)),
    ];

    let attributes = [
        DefaultNla::new(NFTA_EXPR_NAME, nul_terminated("immediate")),
        DefaultNla::new(NFTA_EXPR_DATA | NLA_F_NESTED, encode_attributes(&immediate_attributes)),
    ];

    DefaultNla::new(NFTA_LIST_ELEM | NLA_F_NESTED, encode_attributes(&attributes))
}

/// Builds the table, chain, and expression attributes for a rule.
fn rule_attributes(rule: &Rule<'_>) -> Vec<DefaultNla> {
    let expressions: Vec<DefaultNla> = rule.expressions.iter().map(encode_expression).collect();

    vec![
        DefaultNla::new(NFTA_RULE_TABLE, nul_terminated(&rule.chain.table.name)),
        DefaultNla::new(NFTA_RULE_CHAIN, nul_terminated(&rule.chain.name)),
        DefaultNla::new(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, encode_attributes(&expressions)),
    ]
}

/// Encodes an expression as an entry in the rule's expression list.
fn encode_expression(expression: &Expression) -> DefaultNla {
    match expression {
        Expression::Counter => counter_expression(),
        Expression::Verdict(verdict) => verdict_expression(verdict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Conn;
    use crate::chain::{Chain, ChainHook, ChainPolicy, ChainPriority, ChainType};
    use crate::netlink::decode_messages;
    use crate::{Table, TableFlags};
    use netlink_packet_core::Emitable;
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
            self.replies
                .pop_front()
                .map(|bytes| (bytes, SocketAddr::new(0, 0)))
                .ok_or_else(|| io::Error::other("no prepared acknowledgement"))
        }
    }

    fn connection(sequences: &[u32]) -> Conn<FakeTransport> {
        let replies = sequences
            .iter()
            .map(|sequence| {
                // NLMSG_ERROR with code zero acknowledges a successful operation.
                let mut bytes = 36u32.to_ne_bytes().to_vec();
                bytes.extend_from_slice(&2u16.to_ne_bytes());
                bytes.extend_from_slice(&0u16.to_ne_bytes());
                bytes.extend_from_slice(&sequence.to_ne_bytes());
                bytes.extend_from_slice(&0u32.to_ne_bytes());
                bytes.extend_from_slice(&0i32.to_ne_bytes());
                bytes.extend_from_slice(&16u32.to_ne_bytes());
                bytes.extend_from_slice(&[0; 12]);
                bytes
            })
            .collect();
        Conn {
            transport: FakeTransport {
                replies,
                ..FakeTransport::default()
            },
            sequence: 0,
        }
    }

    fn chain() -> Chain {
        Chain {
            name: "services".into(),
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

    // Expected bytes use literal UAPI identifiers, independent of the encoder.
    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let Ok(length_field) = u16::try_from(length) else {
            panic!("test attribute is too large");
        };
        let mut bytes = length_field.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(length.next_multiple_of(4), 0);
        bytes
    }

    fn expected_counter() -> Vec<u8> {
        let mut fields = attribute(1, b"counter\0");
        fields.extend(attribute(0x8002, &[]));
        attribute(0x8001, &fields)
    }

    fn expected_verdict(code: u8) -> Vec<u8> {
        let verdict = attribute(1, &[0, 0, 0, code]);
        let data = attribute(0x8002, &verdict);
        let mut immediate = attribute(1, &[0, 0, 0, 0]); // Verdict register.
        immediate.extend(attribute(0x8002, &data));
        let mut fields = attribute(1, b"immediate\0");
        fields.extend(attribute(0x8002, &immediate));
        attribute(0x8001, &fields)
    }

    fn expected_rule(family: u8, table: &[u8], chain: &[u8], expressions: &[u8]) -> Vec<u8> {
        let mut bytes = vec![family, 0, 0, 0];
        bytes.extend(attribute(1, table));
        bytes.extend(attribute(2, chain));
        bytes.extend(attribute(0x8004, expressions));
        bytes
    }

    fn emitted(expression: &DefaultNla) -> Vec<u8> {
        let mut bytes = vec![0xff; expression.buffer_len()];
        expression.emit(&mut bytes);
        bytes
    }

    #[test]
    fn counter_expression_encodes_name_and_empty_nested_initial_state() {
        assert_eq!(emitted(&counter_expression()), expected_counter());
    }

    #[test]
    fn verdict_expression_encodes_accept_and_drop_in_network_byte_order() {
        for (verdict, code) in [(Verdict::Accept, 1), (Verdict::Drop, 0)] {
            assert_eq!(emitted(&verdict_expression(&verdict)), expected_verdict(code));
        }
    }

    #[test]
    fn encode_expression_dispatches_each_supported_expression() {
        for (expression, expected) in [
            (Expression::Counter, expected_counter()),
            (Expression::Verdict(Verdict::Accept), expected_verdict(1)),
            (Expression::Verdict(Verdict::Drop), expected_verdict(0)),
        ] {
            assert_eq!(emitted(&encode_expression(&expression)), expected);
        }
    }

    #[test]
    fn rule_attributes_encodes_parent_names_and_preserves_expression_order() {
        let chain = chain();
        let rule = Rule::new(&chain).counter().counter().verdict(Verdict::Drop);
        let attributes = rule_attributes(&rule);
        let mut expressions = expected_counter();
        expressions.extend(expected_counter());
        expressions.extend(expected_verdict(0));
        assert_eq!(attributes.len(), 3);
        assert_eq!(attributes[0], DefaultNla::new(1, b"filter\0".to_vec()));
        assert_eq!(attributes[1], DefaultNla::new(2, b"services\0".to_vec()));
        assert_eq!(attributes[2], DefaultNla::new(0x8004, expressions));
    }

    #[test]
    fn validate_rule_accepts_name_length_boundaries_and_concrete_families() {
        for family in [
            TableFamily::INET,
            TableFamily::IPV4,
            TableFamily::IPV6,
            TableFamily::ARP,
            TableFamily::BRIDGE,
            TableFamily::NETDEV,
        ] {
            for name in ["a".into(), "a".repeat(255), "é".repeat(127) + "a"] {
                let mut chain = chain();
                chain.table.family = family;
                chain.table.name.clone_from(&name);
                chain.name = name;
                assert!(validate_rule(&Rule::new(&chain).counter()).is_ok());
            }
        }
    }

    #[test]
    fn validate_rule_rejects_invalid_table_and_chain_names() {
        for name in [
            String::new(),
            "a".repeat(256),
            "a".repeat(257),
            "é".repeat(128),
            "\0name".into(),
            "na\0me".into(),
            "name\0".into(),
        ] {
            for table_name in [false, true] {
                let mut chain = chain();
                if table_name {
                    chain.table.name.clone_from(&name);
                } else {
                    chain.name.clone_from(&name);
                }
                assert!(matches!(
                    validate_rule(&Rule::new(&chain).counter()),
                    Err(ConnError::InvalidRule(_))
                ));
            }
        }
    }

    #[test]
    fn validate_rule_rejects_unspecified_family() {
        let mut chain = chain();
        chain.table.family = TableFamily::UNSPEC;
        assert!(matches!(
            validate_rule(&Rule::new(&chain).counter()),
            Err(ConnError::InvalidRule(_))
        ));
    }

    #[test]
    fn validate_rule_ignores_parent_creation_options() {
        let mut chain = chain();
        // These are inconsistent creation options, but irrelevant for referencing
        // an already existing chain when adding a rule.
        chain.hooknum = Some(ChainHook::INPUT);
        chain.priority = None;
        chain.chain_type = Some(ChainType::NAT);
        chain.policy = Some(ChainPolicy::DROP);
        chain.device = Some("ignored\0device".into());
        assert!(validate_rule(&Rule::new(&chain).counter()).is_ok());
    }

    #[test]
    fn add_rule_queues_correct_message_flags_family_and_nested_payload() {
        let mut chain = chain();
        chain.table.family = TableFamily::IPV6;
        chain.table.flags = TableFlags::OWNER | TableFlags::PERSIST;
        chain.table.owner = Some(123);
        chain.table.use_count = 42;
        chain.hooknum = Some(ChainHook::INPUT);
        chain.priority = Some(ChainPriority::FILTER);
        chain.chain_type = Some(ChainType::FILTER);
        let mut conn = connection(&[2]);
        let mut batch = conn.batch();
        {
            let rule = Rule::new(&chain).counter().verdict(Verdict::Accept);
            assert!(batch.add_rule(&rule).is_ok());
        } // The batch owns the encoded request, not a reference to this rule.
        assert!(batch.commit().is_ok());
        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid batch");
        };
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].header.message_type, 0x10);
        assert_eq!(messages[2].header.message_type, 0x11);
        assert_eq!(messages[1].header.message_type, 0x0a06); // NEW_RULE.
        assert_eq!(messages[1].header.flags, 0x0c05); // REQUEST | CREATE | APPEND | ACK.
        assert_eq!(messages[1].header.sequence_number, 2);
        let mut expressions = expected_counter();
        expressions.extend(expected_verdict(1));
        let expected = expected_rule(10, b"filter\0", b"services\0", &expressions);
        let NetlinkPayload::InnerMessage(payload) = &messages[1].payload else {
            panic!("expected a rule payload");
        };
        assert_eq!(payload.data, expected);
        assert_eq!(messages[1].header.length as usize, 16 + expected.len());
    }

    #[test]
    fn add_rule_without_commit_sends_nothing_and_assigns_no_sequence() {
        let chain = chain();
        let mut conn = connection(&[]);
        {
            let mut batch = conn.batch();
            assert!(batch.add_rule(&Rule::new(&chain).counter()).is_ok());
            assert!(batch.add_rule(&Rule::new(&chain).verdict(Verdict::Drop)).is_ok());
        }
        assert!(conn.transport.sent.is_empty());
        assert_eq!(conn.sequence, 0);
    }

    #[test]
    fn add_rule_rejects_invalid_input_without_queueing() {
        for name in [String::new(), "a".repeat(256), "é".repeat(128), "na\0me".into()] {
            for table_name in [false, true] {
                let mut chain = chain();
                if table_name {
                    chain.table.name.clone_from(&name);
                } else {
                    chain.name.clone_from(&name);
                }
                let mut conn = connection(&[]);
                let mut batch = conn.batch();
                assert!(matches!(
                    batch.add_rule(&Rule::new(&chain).counter()),
                    Err(ConnError::InvalidRule(_))
                ));
                assert!(batch.commit().is_ok());
                assert!(conn.transport.sent.is_empty());
                assert_eq!(conn.sequence, 0);
            }
        }
        let mut chain = chain();
        chain.table.family = TableFamily::UNSPEC;
        let mut conn = connection(&[]);
        let mut batch = conn.batch();
        assert!(matches!(
            batch.add_rule(&Rule::new(&chain).counter()),
            Err(ConnError::InvalidRule(_))
        ));
        assert!(batch.commit().is_ok());
        assert!(conn.transport.sent.is_empty());
    }

    #[test]
    fn add_rule_validation_failure_preserves_previously_queued_rule() {
        let chain = chain();
        let mut invalid = chain.clone();
        invalid.name = "bad\0name".into();
        let mut conn = connection(&[2]);
        let mut batch = conn.batch();
        assert!(batch.add_rule(&Rule::new(&chain).counter()).is_ok());
        assert!(matches!(
            batch.add_rule(&Rule::new(&invalid).verdict(Verdict::Drop)),
            Err(ConnError::InvalidRule(_))
        ));
        assert!(batch.commit().is_ok());
        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid batch");
        };
        assert_eq!(messages.len(), 3);
        let NetlinkPayload::InnerMessage(payload) = &messages[1].payload else {
            panic!("expected a rule payload");
        };
        assert_eq!(
            payload.data,
            expected_rule(1, b"filter\0", b"services\0", &expected_counter())
        );
    }

    #[test]
    fn add_rule_preserves_order_and_does_not_deduplicate_repeated_rules() {
        let chain = chain();
        let mut conn = connection(&[2, 3, 4]);
        let accept = Rule::new(&chain).verdict(Verdict::Accept);
        let drop = Rule::new(&chain).verdict(Verdict::Drop);
        let mut batch = conn.batch();
        for rule in [&accept, &drop, &accept] {
            assert!(batch.add_rule(rule).is_ok());
        }
        assert!(batch.commit().is_ok());
        assert!(conn.transport.replies.is_empty());
        assert_eq!(conn.transport.sent.len(), 1);
        let Ok(messages) = decode_messages(&conn.transport.sent[0]) else {
            panic!("expected a valid batch");
        };
        assert_eq!(messages.len(), 5);
        for (message, code) in messages[1..4].iter().zip([1, 0, 1]) {
            let NetlinkPayload::InnerMessage(payload) = &message.payload else {
                panic!("expected a rule payload");
            };
            assert_eq!(message.header.message_type, 0x0a06);
            assert_eq!(message.header.flags, 0x0c05);
            assert_eq!(
                payload.data,
                expected_rule(1, b"filter\0", b"services\0", &expected_verdict(code))
            );
        }
    }
}
