use crate::filter::BlockFilter;
use crate::utils::send_protocol_message_with_command_sender;
use crate::{attempt, Status};
use ckb_network::{PeerIndex, CommandSender};
use ckb_types::core::BlockNumber;
use ckb_types::{packed, prelude::*};


const BATCH_SIZE: BlockNumber = 2000;
const CHECK_POINT_INTERVAL: BlockNumber = 2000;

pub struct GetBlockFilterCheckPointsProcess<'a> {
    message: packed::GetBlockFilterCheckPointsReader<'a>,
    filter: &'a BlockFilter,
    command_sender: CommandSender,
    peer: PeerIndex,
}

impl<'a> GetBlockFilterCheckPointsProcess<'a> {
    pub fn new(
        message: packed::GetBlockFilterCheckPointsReader<'a>,
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

        let mut block_filter_hashes = Vec::new();

        if tip_number >= start_number {
            for block_number in (start_number..start_number + BATCH_SIZE * CHECK_POINT_INTERVAL)
                .step_by(CHECK_POINT_INTERVAL as usize)
            {
                if let Some(block_filter_hash) = active_chain
                    .get_block_hash(block_number)
                    .and_then(|block_hash| active_chain.get_block_filter_hash(&block_hash))
                {
                    block_filter_hashes.push(block_filter_hash);
                } else {
                    break;
                }
            }
            let content = packed::BlockFilterCheckPoints::new_builder()
                .start_number(start_number.pack())
                .block_filter_hashes(block_filter_hashes.pack())
                .build();

            let message = packed::BlockFilterMessage::new_builder()
                .set(content)
                .build();
            attempt!(send_protocol_message_with_command_sender(&self.command_sender, self.peer, &message));
        }

        Status::ok()
    }
}
