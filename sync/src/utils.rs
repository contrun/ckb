use crate::{Status, StatusCode};
use ckb_error::{Error as CKBError, ErrorKind, InternalError, InternalErrorKind};
use ckb_logger::error;
use ckb_network::{
    CKBProtocolContext, Command, CommandSender, PeerIndex, ProtocolId, SupportProtocols,
};
use ckb_types::packed::{RelayMessageReader, SyncMessageReader};
use ckb_types::prelude::*;
use std::fmt;
use std::fmt::Formatter;

/// Send network message into parameterized `protocol_id` protocol connection.
///
/// Equal to `nc.send_message`.
#[must_use]
pub(crate) fn send_message<Message: Entity>(
    protocol_id: ProtocolId,
    nc: &dyn CKBProtocolContext,
    peer_index: PeerIndex,
    message: &Message,
) -> Status {
    if let Err(err) = nc.send_message(protocol_id, peer_index, message.as_bytes()) {
        let name = message_name(protocol_id, message);
        let error_message = format!("nc.send_message {name}, error: {err:?}");
        ckb_logger::error!("{}", error_message);
        return StatusCode::Network.with_context(error_message);
    }

    let bytes = message.as_bytes().len() as u64;
    let item_name = item_name(protocol_id, message);
    let protocol_name = protocol_name(protocol_id);
    metric_ckb_message_bytes(
        MetricDirection::Out,
        &protocol_name,
        &item_name,
        None,
        bytes,
    );

    Status::ok()
}

/// Send network message into parameterized `protocol_id` protocol connection.
///
/// Equal to `nc.send_message`.
#[must_use]
pub(crate) fn send_message_with_command_sender<Message: Entity>(
    comand_sender: &CommandSender,
    protocol: SupportProtocols,
    peer_index: PeerIndex,
    message: &Message,
) -> Status {
    if let Err(err) = comand_sender.send(Command::SendMessage {
        protocol,
        peer: peer_index,
        message: message.as_bytes(),
    }) {
        let name = message_name(protocol.protocol_id(), message);
        let error_message = format!("send_message_to_channel {name}, error: {err:?}");
        ckb_logger::error!("{}", error_message);
        return StatusCode::Network.with_context(error_message);
    }

    let bytes = message.as_bytes().len() as u64;
    let item_name = item_name(protocol.protocol_id(), message);
    let protocol_name = protocol.name();
    metric_ckb_message_bytes(
        MetricDirection::Out,
        &protocol_name,
        &item_name,
        None,
        bytes,
    );

    Status::ok()
}

pub(crate) enum MetricDirection {
    In,
    Out,
}

impl fmt::Display for MetricDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MetricDirection::In => write!(f, "in"),
            MetricDirection::Out => write!(f, "out"),
        }
    }
}

pub(crate) fn metric_ckb_message_bytes(
    direction: MetricDirection,
    protocol_name: &str,
    item_name: &str,
    status_code: Option<StatusCode>,
    bytes: u64,
) {
    if let Some(metrics) = ckb_metrics::handle() {
        metrics
            .ckb_message_bytes
            .with_label_values(&[
                direction.to_string().as_str(),
                protocol_name,
                item_name,
                &status_code.unwrap_or(StatusCode::Ignored).name(),
            ])
            .observe(bytes as f64);
    }
}

/// Send network message into `nc.protocol_id()` protocol connection.
///
/// Equal to `nc.send_message_to`.
#[must_use]
pub(crate) fn send_message_to<Message: Entity>(
    nc: &dyn CKBProtocolContext,
    peer_index: PeerIndex,
    message: &Message,
) -> Status {
    // TOOD: don't hard code this
    let protocol = SupportProtocols::Sync;
    send_message(protocol.protocol_id(), nc, peer_index, message)
}

/// Send network message into `nc.protocol_id()` protocol connection.
///
/// Equal to `nc.send_message_to`.
#[must_use]
pub(crate) fn send_protocol_message_with_command_sender<Message: Entity>(
    command_sender: &CommandSender,
    peer_index: PeerIndex,
    message: &Message,
) -> Status {
    send_message_with_command_sender(
        command_sender,
        command_sender.protocol(),
        peer_index,
        message,
    )
}

// As for Sync protocol and Relay protocol, returns the internal item name;
// otherwise returns the entity name.
fn message_name<Message: Entity>(protocol_id: ProtocolId, message: &Message) -> String {
    if protocol_id == SupportProtocols::Sync.protocol_id() {
        SyncMessageReader::new_unchecked(message.as_slice())
            .to_enum()
            .item_name()
            .to_owned()
    } else if protocol_id == SupportProtocols::RelayV2.protocol_id()
        || protocol_id == SupportProtocols::RelayV3.protocol_id()
    {
        RelayMessageReader::new_unchecked(message.as_slice())
            .to_enum()
            .item_name()
            .to_owned()
    } else {
        Message::NAME.to_owned()
    }
}

// As for Sync protocol and Relay protocol, returns the internal item_name;
// otherwise returns none.
fn item_name<Message: Entity>(protocol_id: ProtocolId, message: &Message) -> String {
    if protocol_id == SupportProtocols::Sync.protocol_id() {
        SyncMessageReader::verify(message.as_slice(), true)
            .map(|_| {
                SyncMessageReader::new_unchecked(message.as_slice())
                    .to_enum()
                    .item_name()
                    .to_owned()
            })
            .unwrap_or_else(|err| {
                error!("SyncMessageReader::verify error: {:?}", err);
                "none".to_owned()
            })
    } else if protocol_id == SupportProtocols::RelayV2.protocol_id() {
        RelayMessageReader::verify(message.as_slice(), true)
            .map(|_| {
                RelayMessageReader::new_unchecked(message.as_slice())
                    .to_enum()
                    .item_name()
                    .to_owned()
            })
            .unwrap_or_else(|err| {
                error!("RelayMessageReader::verify error: {:?}", err);
                "none".to_owned()
            })
    } else {
        "none".to_owned()
    }
}

fn protocol_name(protocol_id: ProtocolId) -> String {
    match protocol_id.value() {
        0 => SupportProtocols::Ping.name(),
        1 => SupportProtocols::Discovery.name(),
        2 => SupportProtocols::Identify.name(),
        3 => SupportProtocols::Feeler.name(),
        4 => SupportProtocols::DisconnectMessage.name(),
        100 => SupportProtocols::Sync.name(),
        101 => SupportProtocols::RelayV2.name(),
        102 => SupportProtocols::Time.name(),
        103 => SupportProtocols::RelayV3.name(),
        110 => SupportProtocols::Alert.name(),
        120 => SupportProtocols::LightClient.name(),
        121 => SupportProtocols::Filter.name(),
        _ => {
            error!("send_message got an unknown protocol id: {}", protocol_id);
            "Unknown".to_owned()
        }
    }
}

/// return whether the error's kind is `InternalErrorKind::Database`
///
/// ### Panic
///
/// Panic if the error kind is `InternalErrorKind::DataCorrupted`.
/// If the database is corrupted, panic is better than handle it silently.
pub(crate) fn is_internal_db_error(error: &CKBError) -> bool {
    if error.kind() == ErrorKind::Internal {
        let error_kind = error
            .downcast_ref::<InternalError>()
            .expect("error kind checked")
            .kind();
        if error_kind == InternalErrorKind::DataCorrupted {
            panic!("{}", error)
        } else {
            return error_kind == InternalErrorKind::Database
                || error_kind == InternalErrorKind::System;
        }
    }
    false
}
