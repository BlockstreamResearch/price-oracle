use std::fmt;

#[derive(Debug)]
pub struct CommandOutput {
    message: &'static str,
}

impl CommandOutput {
    pub(super) fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for CommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}
