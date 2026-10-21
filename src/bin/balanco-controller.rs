//! Optional standalone Jev/Laya control process; keep inference on a separate CPU budget.
use balanco::{
    Error,
    adapter::{Client, Config, Controller},
};
use std::{io::Read, time::Duration};
fn main() {
    if let Err(error) = run() {
        eprintln!("balanco-controller: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !(1..=2).contains(&args.len()) || args.get(1).is_some_and(|v| v != "--once") {
        return Err("usage: balanco-controller CONFIG [--once]".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&args[0])?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err("controller config exceeds 1 MiB".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    config.validate()?;
    let management = Client::new(config.management.clone(), config.timeout_ms, true)?;
    let model = Client::new(config.model.clone(), config.timeout_ms, false)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut controller = Controller::default();
            loop {
                let result = controller.tick(&config, &management, &model).await;
                if args.len() == 2 {
                    return result;
                }
                if let Err(error) = result {
                    controller.failed();
                    eprintln!("routing update skipped: {error}");
                }
                tokio::time::sleep(Duration::from_millis(config.interval_ms)).await;
            }
        })
}
