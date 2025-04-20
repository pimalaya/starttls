use std::{
    env,
    io::{stdin, stdout, Read, Write},
    net::TcpStream,
    sync::Arc,
};

use log::info;
use native_tls::TlsConnector;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use starttls_flows::imap::UpgradeTls;
use stream_flows::{handlers::std::Handler, State};

fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "debug");
    }

    env_logger::init();

    let host = match env::var("HOST") {
        Ok(host) => host,
        Err(_) => read_line("TCP server hostname?"),
    };

    let port: u16 = match env::var("PORT") {
        Ok(port) => port.parse().unwrap(),
        Err(_) => read_line("TCP server port?").parse().unwrap(),
    };

    let mut tcp = TcpStream::connect((host.as_str(), port)).unwrap();
    let mut starttls = UpgradeTls::new().with_discard_greeting(true);

    while let Err(io) = starttls.next() {
        Handler::handle(&mut tcp, &mut starttls, io).unwrap();
    }

    info!("upgrade current TCP stream to TLS");
    let mut tls = upgrade_tls(host, tcp);

    let mut state = State::default();
    info!("send NOOP command via TLS");
    state.enqueue_bytes(b"A NOOP\r\n");
    Handler::write(&mut tls, &mut state).unwrap();

    let n = Handler::read(&mut tls, &mut state).unwrap();
    let bytes = String::from_utf8_lossy(state.get_read_bytes(n));
    info!("receive NOOP response via TLS: {bytes:?}");
}

fn read_line(prompt: &str) -> String {
    print!("{prompt} ");
    stdout().flush().unwrap();

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();

    line.trim().to_owned()
}

trait StreamExt: Read + Write {}
impl<T: Read + Write> StreamExt for T {}

fn upgrade_tls(host: impl ToString, tcp: TcpStream) -> Box<dyn StreamExt> {
    match env::var("CRYPTO") {
        Ok(crypto) if crypto.eq_ignore_ascii_case("native-tls") => {
            info!("using native TLS");
            let connector = TlsConnector::new().unwrap();
            let tls = connector.connect(&host.to_string(), tcp).unwrap();
            Box::new(tls)
        }
        _ => {
            info!("using rustls");
            let config = ClientConfig::with_platform_verifier();
            let server_name = host.to_string().try_into().unwrap();
            let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
            let tls = StreamOwned::new(conn, tcp);
            Box::new(tls)
        }
    }
}
