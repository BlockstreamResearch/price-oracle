use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{MessageContext, StormMessage, StormState, message::StormErrorCode};

pub(super) async fn handle(
    _state: &Arc<RwLock<StormState>>,
    _context: MessageContext,
    _message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    Ok(())
}
