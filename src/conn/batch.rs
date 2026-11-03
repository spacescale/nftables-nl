//! Batched nftables write operations.
//!
//! A batch queues operations locally without sending them to the kernel.
//! Committing sends the queued operations in order, wrapped in Netfilter
//! batch begin and end messages, as one atomic transaction.
//!
//! The kernel applies all changes together or rejects the transaction.
//! Commit waits for kernel acknowledgements and reports transport or
//! kernel errors.
//!
//! Dropping a batch without committing discards its queued operation
//! # References
//! https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals#Serialization_into_netlink_messages

use crate::conn::Transport;
use crate::netlink::decode_messages;
use crate::types::{NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NfGenMsg, NftMessage};
use crate::{Conn, ConnError};
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use std::collections::HashSet;

enum BatchBoundary {
    Begin,
    End,
}

#[must_use = "a batch does nothing unless committed"]
pub struct Batch<'a, T> {
    conn: &'a mut Conn<T>,
    messages: Vec<NetlinkMessage<NftMessage>>,
}

// Transport is internal; callers use the socket-backed connection.
#[allow(private_bounds)]
impl<'a, T: Transport> Batch<'a, T> {
    /// Sends the queued operations as one transaction and waits for acknowledgements.
    pub fn commit(self) -> Result<(), ConnError> {
        // An empty batch has nothing to send.
        if self.messages.is_empty() {
            return Ok(());
        }

        let mut operations = self.messages;

        // Require acknowledgement for every queued operation.
        for message in &mut operations {
            message.header.flags |= NLM_F_ACK;
        }

        // Surround operations with BEGIN and END.
        let mut messages = frame_batch(operations);

        // Number every message before serializing it.
        self.conn.assign_sequence(&mut messages);

        // Include boundaries so their kernel errors are recognized too.
        let mut batch_sequences = HashSet::new();
        for message in &messages {
            batch_sequences.insert(message.header.sequence_number);
        }

        let pending = pending_acknowledgement(&messages);
        let bytes = serialize_batch(&mut messages);

        let sent = self.conn.transport.send_request(&bytes).map_err(ConnError::Send)?;
        if sent != bytes.len() {
            return Err(ConnError::Send(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "incomplete batch send",
            )));
        }

        receive_acknowledgements(&mut self.conn.transport, &batch_sequences, pending)
    }

    /// Queues an operation without sending it to the kernel.
    ///
    /// The message is finalized, assigned a sequence number, and sent
    /// when the batch is committed.
    pub(super) fn push(&mut self, message: NetlinkMessage<NftMessage>) {
        self.messages.push(message)
    }
}

impl<T> Conn<T> {
    pub fn batch(&mut self) -> Batch<'_, T> {
        Batch {
            conn: self,
            messages: Vec::new(),
        }
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1);
        if self.sequence == 0 {
            self.sequence = 1;
        }
        self.sequence
    }

    fn assign_sequence(&mut self, messages: &mut [NetlinkMessage<NftMessage>]) {
        for message in messages {
            message.header.sequence_number = self.next_sequence();
        }
    }
}

/// Builds a batch BEGIN or END message.
///
/// `message_type` is NFNL_MSG_BATCH_BEGIN or NFNL_MSG_BATCH_END.
/// For batch boundaries, res_id identifies the target subsystem:
/// nftables (10), encoded in big-endian order by NfGenMsg::encode()
fn batch_boundary(boundary: BatchBoundary) -> NetlinkMessage<NftMessage> {
    let message_type = match boundary {
        BatchBoundary::Begin => NFNL_MSG_BATCH_BEGIN,
        BatchBoundary::End => NFNL_MSG_BATCH_END,
    };

    let nfgen = NfGenMsg {
        nfgen_family: 0,
        version: 0,
        res_id: NFNL_SUBSYS_NFTABLES,
    };

    let payload = NftMessage {
        message_type,
        data: nfgen.encode().to_vec(),
    };

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST;

    let mut message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(payload));

    message.finalize();
    message
}

/// Wraps queued operations in Netfilter transaction boundaries.
/// Preserves the order in which operations were queued.
fn frame_batch(messages: Vec<NetlinkMessage<NftMessage>>) -> Vec<NetlinkMessage<NftMessage>> {
    let mut framed = Vec::with_capacity(messages.len() + 2);
    framed.push(batch_boundary(BatchBoundary::Begin));
    framed.extend(messages);
    framed.push(batch_boundary(BatchBoundary::End));

    framed
}

/// Serializes messages into one buffer, aligning each to four bytes
fn serialize_batch(messages: &mut [NetlinkMessage<NftMessage>]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for message in messages {
        message.finalize();
        let start = bytes.len();
        let length = message.buffer_len();

        // Round the space occupied by this message up to four bytes
        let padding = (4 - length % 4) % 4;
        bytes.resize(start + length + padding, 0);

        message.serialize(&mut bytes[start..start + length]);
    }

    bytes
}

/// Collects sequence numbers of messages requesting acknowledgement.
fn pending_acknowledgement(messages: &[NetlinkMessage<NftMessage>]) -> HashSet<u32> {
    let mut pending = HashSet::new();

    for message in messages {
        if message.header.flags & NLM_F_ACK != 0 {
            pending.insert(message.header.sequence_number);
        }
    }
    pending
}

/// Handles a reply already matched to the current batch
fn handle_acknowledgement(message: NetlinkMessage<NftMessage>, pending: &mut HashSet<u32>) -> Result<(), ConnError> {
    let sequence = message.header.sequence_number;

    match message.payload {
        NetlinkPayload::Error(error) if error.code.is_some() => return Err(ConnError::Kernel(error.to_io())),
        NetlinkPayload::Error(_) => {
            pending.remove(&sequence);
        }
        NetlinkPayload::Overrun(_) => return Err(ConnError::Overrun),

        _ => {}
    }

    Ok(())
}

/// Receives replies until all requested acknowledgements arrive,
/// or a transport, decoding, or kernel error occurs.
fn receive_acknowledgements(
    transport: &mut impl Transport,
    batch_sequences: &HashSet<u32>,
    mut pending: HashSet<u32>,
) -> Result<(), ConnError> {
    while !pending.is_empty() {
        let (bytes, sender) = transport.receive_reply().map_err(ConnError::Recv)?;

        // Kernel Netlink messages come from port ID zero.
        if sender.port_number() != 0 {
            continue;
        }

        let replies = decode_messages(&bytes).map_err(ConnError::Decode)?;

        for reply in replies {
            // Ignore messages unrelated to this transaction.
            if !batch_sequences.contains(&reply.header.sequence_number) {
                continue;
            }

            handle_acknowledgement(reply, &mut pending)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_sys::SocketAddr;
    use std::collections::VecDeque;
    use std::io;

    #[derive(Default)]
    struct FakeTransport {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
        fail_send: bool,
    }

    impl Transport for FakeTransport {
        fn send_request(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_send {
                return Err(io::Error::other("simulated send failure"));
            }

            self.sent.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn receive_reply(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
            let bytes = self
                .replies
                .pop_front()
                .ok_or_else(|| io::Error::other("no prepared reply"))?;

            Ok((bytes, SocketAddr::new(0, 0)))
        }
    }

    /// A placeholder operation for testing transport behavior.
    /// It is never sent to a real kernel.
    fn fake_operation() -> NetlinkMessage<NftMessage> {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST;

        NetlinkMessage::new(
            header,
            NetlinkPayload::InnerMessage(NftMessage {
                message_type: 0x0a00, // nftables NEW_TABLE.
                data: vec![1, 0, 0, 0],
            }),
        )
    }

    /// Independently constructs an NLMSG_ERROR reply.
    /// Code zero means success; a negative errno means failure.
    fn acknowledgement(sequence: u32, code: i32) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&36u32.to_ne_bytes()); // Total length.
        bytes.extend_from_slice(&2u16.to_ne_bytes()); // NLMSG_ERROR.
        bytes.extend_from_slice(&0u16.to_ne_bytes()); // Flags.
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // Kernel port ID.

        bytes.extend_from_slice(&code.to_ne_bytes());

        // Original request header included in an NLMSG_ERROR payload.
        bytes.extend_from_slice(&16u32.to_ne_bytes());
        bytes.extend_from_slice(&[0; 12]);

        bytes
    }

    #[test]
    fn prepares_batch_boundaries() {
        // These helpers don't use a socket, so () is enough here.
        let mut conn = Conn {
            transport: (),
            sequence: 0,
        };

        let mut messages = frame_batch(Vec::new());
        conn.assign_sequence(&mut messages);

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].header.message_type, NFNL_MSG_BATCH_BEGIN);
        assert_eq!(messages[1].header.message_type, NFNL_MSG_BATCH_END);

        assert_eq!(messages[0].header.sequence_number, 1);
        assert_eq!(messages[1].header.sequence_number, 2);

        let bytes = serialize_batch(&mut messages);

        // Two boundaries, each with a 16-byte header + 4-byte payload.
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn commit_sends_operations_in_order_and_waits_for_acknowledgements() {
        let mut conn = Conn {
            transport: FakeTransport {
                // BEGIN gets sequence 1, operations get 2 and 3, END gets 4.
                replies: VecDeque::from([acknowledgement(2, 0), acknowledgement(3, 0)]),
                ..Default::default()
            },
            sequence: 0,
        };

        let mut batch = conn.batch();
        batch.messages.push(fake_operation());
        batch.messages.push(fake_operation());

        batch.commit().expect("both operations acknowledged");

        assert_eq!(conn.transport.sent.len(), 1);
        assert!(conn.transport.replies.is_empty());

        let sent = decode_messages(&conn.transport.sent[0]).expect("valid serialized batch");

        assert_eq!(sent.len(), 4);
        assert_eq!(sent[0].header.message_type, NFNL_MSG_BATCH_BEGIN);
        assert_eq!(sent[1].header.message_type, 0x0a00);
        assert_eq!(sent[2].header.message_type, 0x0a00);
        assert_eq!(sent[3].header.message_type, NFNL_MSG_BATCH_END);

        for (message, expected) in sent.iter().zip(1u32..=4) {
            assert_eq!(message.header.sequence_number, expected);
        }

        assert_ne!(sent[1].header.flags & NLM_F_ACK, 0);
        assert_ne!(sent[2].header.flags & NLM_F_ACK, 0);
    }

    #[test]
    fn commit_reports_kernel_error_on_batch_boundary() {
        let mut conn = Conn {
            transport: FakeTransport {
                // An error on BEGIN must be recognized even without its ACK flag.
                replies: VecDeque::from([acknowledgement(1, -22)]),
                ..Default::default()
            },
            sequence: 0,
        };

        let mut batch = conn.batch();
        batch.messages.push(fake_operation());

        match batch.commit() {
            Err(ConnError::Kernel(error)) => {
                assert_eq!(error.raw_os_error(), Some(22));
            }
            other => panic!("expected kernel EINVAL, got {other:?}"),
        }
    }

    #[test]
    fn empty_commit_sends_nothing() {
        let mut conn = Conn {
            transport: FakeTransport::default(),
            sequence: 0,
        };

        conn.batch().commit().expect("empty batch succeeds");

        assert!(conn.transport.sent.is_empty());
        assert_eq!(conn.sequence, 0);
    }

    #[test]
    fn commit_reports_send_failure() {
        let mut conn = Conn {
            transport: FakeTransport {
                fail_send: true,
                ..Default::default()
            },
            sequence: 0,
        };

        let mut batch = conn.batch();
        batch.messages.push(fake_operation());

        assert!(matches!(batch.commit(), Err(ConnError::Send(_))));
    }
}
