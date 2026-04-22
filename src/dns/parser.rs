use anyhow::{Context, Result};
use bytes::Bytes;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

/// Parse a DNS wire-format message from raw bytes.
pub fn parse_dns_message(data: &[u8]) -> Result<Message> {
    Message::from_bytes(data).context("Failed to parse DNS message")
}

/// Encode a DNS message back to wire format.
pub fn encode_dns_message(msg: &Message) -> Result<Bytes> {
    let bytes = msg
        .to_bytes()
        .context("Failed to encode DNS message")?;
    Ok(Bytes::from(bytes))
}

/// Extract the first query name and record type as strings (for logging/cache keys).
pub fn query_info(msg: &Message) -> Option<(String, String)> {
    let query = msg.queries().first()?;
    let name = query.name().to_string();
    let qtype = query.query_type().to_string();
    Some((name, qtype))
}

/// Compute the minimum TTL across all answer records.
/// Returns None if there are no answer records.
pub fn min_answer_ttl(msg: &Message) -> Option<u32> {
    let answers = msg.answers();
    if answers.is_empty() {
        return None;
    }
    answers.iter().map(|rr| rr.ttl()).min()
}

/// Build a SERVFAIL response for a given request message.
pub fn build_servfail(request: &Message) -> Result<Bytes> {
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};

    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::ServFail);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    encode_dns_message(&response)
}
