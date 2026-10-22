//! Table operations and their transport-based listing workflow.

use super::{Conn, ConnError, Transport};
use crate::netlink::decode_messages;
use crate::table::{Table, TableFamily};
use crate::types::{NfGenMsg, NftMessage, NftMsgType};
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use std::io;

impl Conn {
    /// Returns all currently configured nftables.
    pub fn list_tables(&mut self) -> Result<Vec<Table>, ConnError> {
        self.list_tables_of_family(TableFamily::UNSPEC)
    }

    pub fn list_tables_of_family(&mut self, family: TableFamily) -> Result<Vec<Table>, ConnError> {
        list_tables_with_transport(&mut self.socket, family)
    }
}

/// Runs the same listing workflow with either a real or fake transport.
fn list_tables_with_transport(
    transport: &mut impl Transport,
    family: TableFamily,
) -> Result<Vec<Table>, ConnError> {
    let nfgen = NfGenMsg {
        nfgen_family: family.as_raw(),
        version: 0,
        res_id: 0,
    };

    let payload = NftMessage {
        message_type: NftMsgType::GET_TABLE.header_type(),
        data: nfgen.encode().to_vec(),
    };

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(payload));

    message.finalize(); // copies nft message header into the netlink header struct header field

    // magic where header type is copied into the netlink header
    let mut buf = vec![0u8; message.buffer_len()];
    message.serialize(&mut buf[..]);

    // Production sends through Socket; tests can record these bytes.
    transport.send_request(&buf).map_err(ConnError::Send)?;

    let mut tables = Vec::new();

    // Outer loop: receive datagrams until the kernel says the dump is done.
    loop {
        let (reply, _) = transport.receive_reply().map_err(ConnError::Recv)?;
        let messages = decode_messages(&reply).map_err(ConnError::Decode)?;
        for message in messages {
            // Check the reply header before handling its payload.
            if message.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(ConnError::DumpInterrupted);
            }

            match message.payload {
                NetlinkPayload::InnerMessage(nft_message) => {
                    // kernel treats all retuned table as new table
                    if nft_message.message_type != NftMsgType::NEW_TABLE.header_type() {
                        return Err(ConnError::UnexpectedMessageType(nft_message.message_type));
                    }

                    let table = Table::from_message(&nft_message)?;
                    tables.push(table);
                }

                NetlinkPayload::Done(done) if done.code == 0 => return Ok(tables),

                NetlinkPayload::Overrun(_) => return Err(ConnError::Overrun),

                // other exit code should fail
                NetlinkPayload::Done(done) => {
                    return Err(ConnError::Kernel(io::Error::from_raw_os_error(-done.code)));
                }

                NetlinkPayload::Error(error) if error.code.is_some() => {
                    return Err(ConnError::Kernel(error.to_io()));
                }

                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_sys::SocketAddr;
    use std::collections::VecDeque;

    // Build fixture bytes independently of the production serializer.
    fn reply(message_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&message_type.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // Sequence.
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // Port ID.
        bytes.extend_from_slice(payload);
        bytes
    }

    fn done_reply(code: i32) -> Vec<u8> {
        // NLMSG_DONE = 3, NLM_F_MULTI = 2; status uses native byte order.
        reply(3, 2, &code.to_ne_bytes())
    }

    fn table_reply(name: &str) -> Vec<u8> {
        let mut payload = vec![1, 0, 0, 0]; // INET nfgenmsg.

        // NFTA_TABLE_NAME = 1: attribute header + name + terminating NUL.
        let attribute_len = 4 + name.len() + 1;
        payload.extend_from_slice(
            &u16::try_from(attribute_len)
                .expect("fixture name fits in an attribute")
                .to_ne_bytes(),
        );
        payload.extend_from_slice(&1u16.to_ne_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);

        // Attribute length excludes padding; the next attribute is aligned.
        let padding = (4 - attribute_len % 4) % 4;
        payload.resize(payload.len() + padding, 0);

        reply(0x0a00, 2, &payload) // NEW_TABLE, NLM_F_MULTI.
    }

    #[derive(Default)]
    struct FakeTransport {
        // Requests sent by the workflow, saved so tests can inspect them
        sent_requests: Vec<Vec<u8>>,

        // Each receive calls removes and returns the next prepared result
        replies: VecDeque<io::Result<(Vec<u8>, SocketAddr)>>,
    }

    impl Transport for FakeTransport {
        fn send_request(&mut self, bytes: &[u8]) -> io::Result<usize> {
            // Record  the request instead of sending anything to the kernel
            self.sent_requests.push(bytes.to_vec());

            // Simulate the socket accepting all request bytes.
            Ok(bytes.len())
        }

        fn receive_reply(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
            // Return the next prepared datagram or I/O error.
            // An unexpected receive fails the test instead of waiting forever.
            self.replies
                .pop_front()
                .expect("workflow received more times than the test expected")
        }
    }

    impl FakeTransport {
        fn with_replies(replies: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                sent_requests: Vec::new(),
                replies: replies
                    .into_iter()
                    .map(|bytes| Ok((bytes, SocketAddr::new(0, 0))))
                    .collect(),
            }
        }
    }

    #[test]
    fn request_inet_tables_and_finish_on_empty_dump() {
        let mut fake = FakeTransport::with_replies([done_reply(0)]);

        // Executes the same workflow that Conn uses with its real socket
        let tables = list_tables_with_transport(&mut fake, TableFamily::INET)
            .expect("empty dump should succeed");

        // Successful completion without table messages produces an empty list
        assert!(tables.is_empty());

        // the workflow must send exactly one request.
        assert_eq!(fake.sent_requests.len(), 1);

        // Inspect the actual request generated by the workflow.
        let request = NetlinkMessage::<NftMessage>::deserialize(&fake.sent_requests[0])
            .expect("workflow should send a valid Netlink request");

        assert_eq!(request.header.length, 20);
        assert_eq!(request.header.message_type, 0x0a01); // GET_TABLE.
        assert_eq!(request.header.flags, NLM_F_REQUEST | NLM_F_DUMP);
        match request.payload {
            NetlinkPayload::InnerMessage(message) => {
                // nfgenmsg: INET family, version 0, resource ID 0.
                assert_eq!(message.data, vec![1, 0, 0, 0]);
            }
            other => panic!("expected an nftables request, got {other:?}"),
        }

        // The prepared Done reply must have been consumed.
        assert!(fake.replies.is_empty());
    }

    #[test]
    fn collects_table_before_finishing_dump() {
        // Separate datagrams ensure the workflow continues receiving.
        let mut fake = FakeTransport::with_replies([table_reply("filter"), done_reply(0)]);

        let tables = list_tables_with_transport(&mut fake, TableFamily::INET)
            .expect("table dump should succeed");

        assert_eq!(tables.len(), 1);
        let table = &tables[0];
        assert_eq!(table.name, "filter");
        assert_eq!(table.family, TableFamily::INET);

        // These optional attributes were absent, so defaults should be used.
        assert_eq!(table.flags.as_raw(), 0);
        assert_eq!(table.use_count, 0);
        assert_eq!(table.owner, None);

        assert_eq!(fake.sent_requests.len(), 1);

        // Both replies must have been consumed.
        // This catches returning immediately after the table instead of
        // continuing to receive the final Done message.
        assert!(fake.replies.is_empty());
    }

    #[test]
    fn returns_kernel_error_when_dump_completion_fails() {
        // Linux ENOMEM = 12. The kernel encodes errors as negative numbers.
        let mut fake = FakeTransport::with_replies([done_reply(-12)]);

        let result = list_tables_with_transport(&mut fake, TableFamily::INET);

        match result {
            Err(ConnError::Kernel(error)) => {
                assert_eq!(error.raw_os_error(), Some(12));
            }
            _ => panic!("expected a kernel error from failed completion"),
        }

        assert!(fake.replies.is_empty());
    }
}
