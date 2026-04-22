use anyhow::Result;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Build a minimal NXDOMAIN response.
pub fn build_nxdomain(request: &Message) -> Result<Bytes> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NXDomain);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    crate::dns::parser::encode_dns_message(&response)
}

/// Build a simple A-record response (for testing / synthetic responses).
pub fn build_a_response(request: &Message, ip: std::net::Ipv4Addr, ttl: u32) -> Result<Bytes> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(ResponseCode::NoError);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    if let Some(query) = request.queries().first() {
        let name: Name = query.name().clone();
        let mut record = Record::new();
        record.set_name(name);
        record.set_ttl(ttl);
        record.set_record_type(RecordType::A);
        record.set_data(Some(RData::A(ip.into())));
        response.add_answer(record);
    }

    crate::dns::parser::encode_dns_message(&response)
}
