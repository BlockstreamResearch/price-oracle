mod cli;
mod commands;
mod error;

use clap::Parser;
use cli::Cli;
use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let output = cli.command.execute(&cli.socket).await?;
    println!("{output}");
    Ok(())
}
