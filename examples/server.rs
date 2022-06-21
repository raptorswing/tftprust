use tftprust::server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = server::TFTPServer::new("0.0.0.0:69")?;

    let res = server.run().await;
    if res.is_err() {
        eprintln!("Server stopped with error: {:?}", res.err());
        std::process::exit(1);
    }
    Ok(())
}
