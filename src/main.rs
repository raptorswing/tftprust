mod tftp_server;
use tftp_server::make_tftp_server;

fn main() {
    let mut server = make_tftp_server("0.0.0.0:69");

    let res = server.run();
    if res.is_err() {
        eprintln!("Server stopped with error: {:?}", res.err());
        std::process::exit(1);
    }
}