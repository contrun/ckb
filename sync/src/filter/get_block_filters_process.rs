use crate::filter::BlockFilter;
use crate::utils::send_protocol_message_with_command_sender;
use crate::{attempt, Status};
use ckb_network::{CommandSender, PeerIndex};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*};

const BATCH_SIZE: BlockNumber = 1000;

pub struct GetBlockFiltersProcess<'a> {
    message: packed::GetBlockFiltersReader<'a>,
    filter: &'a BlockFilter,
    command_sender: CommandSender,
    peer: PeerIndex,
}

impl<'a> GetBlockFiltersProcess<'a> {
    pub fn new(
        message: packed::GetBlockFiltersReader<'a>,
        filter: &'a BlockFilter,
        command_sender: CommandSender,
        peer: PeerIndex,
    ) -> Self {
        Self {
            message,
            command_sender,
            filter,
            peer,
        }
    }

    pub fn execute(self) -> Status {
        let active_chain = self.filter.shared.active_chain();
        let start_number: BlockNumber = self.message.to_entity().start_number().unpack();
        let tip_number: BlockNumber = active_chain.tip_number();
        if tip_number >= start_number {
            let mut block_hashes = Vec::new();
            let mut filters = Vec::new();
            for block_number in start_number..start_number + BATCH_SIZE {
                if let Some(block_hash) = active_chain.get_block_hash(block_number) {
                    if let Some(block_filter) = active_chain.get_block_filter(&block_hash) {
                        block_hashes.push(block_hash);
                        filters.push(block_filter);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            let content = packed::BlockFilters::new_builder()
                .start_number(start_number.pack())
                .block_hashes(block_hashes.pack())
                .filters(filters.pack())
                .build();

            let message = packed::BlockFilterMessage::new_builder()
                .set(content)
                .build();
            attempt!(send_protocol_message_with_command_sender(
                &self.command_sender,
                self.peer,
                &message
            ));
        }

        Status::ok()
    }
}
