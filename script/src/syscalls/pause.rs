use crate::syscalls::DEBUG_PAUSE;
use ckb_vm::{registers::A7, Error as VMError, Register, SupportMachine, Syscalls};
use std::cell::RefCell;
use std::sync::Arc;

#[derive(Debug)]
pub struct Pause {
    skip: Arc<RefCell<bool>>,
}

impl Pause {
    pub fn new(skip: Arc<RefCell<bool>>) -> Self {
        Self { skip }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for Pause {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        if machine.registers()[A7].to_u64() != DEBUG_PAUSE {
            return Ok(false);
        }
        if *self.skip.borrow() {
            return Ok(true);
        }
        Err(VMError::CyclesExceeded)
    }
}
