use anyhow::anyhow;
use async_std::fs::File;
use async_std::future::timeout;
use async_std::net::Ipv4Addr;
use async_std::net::SocketAddr;
use async_std::net::ToSocketAddrs;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use futures::executor::block_on;
use futures::executor::ThreadPool;
use std::convert::TryFrom;
use std::string;
use std::time::{Duration, Instant};
use tftprust::packets::{TFTPMode, TFTPPacket};

const MAX_DATA_SIZE: usize = 512;
const DATA_HEADER_SIZE: usize = 4;
const MAX_DATA_PACKET_SIZE: usize = MAX_DATA_SIZE + DATA_HEADER_SIZE;

const MAX_ACK_TIMEOUT_SECS: u64 = 10;

type TFTPBuffer = [u8; MAX_DATA_PACKET_SIZE];

pub struct TFTPServer {
    socket: UdpSocket,
    buf: TFTPBuffer,
}

impl TFTPServer {
    pub fn run(&mut self) -> anyhow::Result<()> {
        let pool = ThreadPool::new()?;

        loop {
            match self.main_loop_iter(&pool) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error processing incoming request: {}", e);
                }
            }
        }
    }

    //
    fn main_loop_iter(&mut self, pool: &ThreadPool) -> anyhow::Result<()> {
        let (num_recv_bytes, sender) = block_on(self.socket.recv_from(&mut self.buf))?;
        let data = self.buf[0..num_recv_bytes].to_vec();
        // println!("Received {} bytes from {:?}: {:?}", num_recv_bytes, sender, &self.buf[..num_recv_bytes]);

        // Parse bytes into packet
        let packet = TFTPPacket::try_from(data)?;

        eprintln!("Received {:?} from {:?}", packet, sender);

        // Take action based on packet
        match packet {
            TFTPPacket::ReadRequest(filename, mode) => {
                pool.spawn_ok(TFTPServer::spawn_wrap(TFTPServer::handle_read_request(
                    sender, filename, mode,
                )));
                Ok(())
            }

            _ => Err(anyhow!("Unsupported operation")),
        }
    }

    async fn spawn_wrap<Fut>(future: Fut)
    where
        Fut: Future<Output = anyhow::Result<()>>,
    {
        match future.await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error during request processing: {}", e);
            }
        }
    }

    async fn handle_read_request(
        remote: SocketAddr,
        filename: string::String,
        mode: TFTPMode,
    ) -> anyhow::Result<()> {
        eprintln!("Time to handle a read request");
        if mode != TFTPMode::Octet {
            return Err(anyhow!("Only octet mode is supported for now"));
        }

        let broadcast_addr = (Ipv4Addr::new(0, 0, 0, 0), 0);
        let client_socket = UdpSocket::bind(broadcast_addr).await?;
        client_socket.connect(remote).await?;

        let mut file = File::open(filename).await?;

        let mut block_count: u16 = 1;
        let mut to_send: TFTPBuffer = [0; MAX_DATA_PACKET_SIZE];
        to_send[1] = 3;
        loop {
            let block_count_be_bytes = block_count.to_be_bytes();
            to_send[2] = block_count_be_bytes[0];
            to_send[3] = block_count_be_bytes[1];
            block_count += 1;

            let num_read_from_file = file
                .read(&mut to_send[DATA_HEADER_SIZE..MAX_DATA_SIZE + DATA_HEADER_SIZE])
                .await?;

            // Write the data to our buddy
            let data_packet = &to_send[..num_read_from_file + DATA_HEADER_SIZE];
            client_socket.send(data_packet).await?;

            // Wait for ack, retransmitting as necessary
            TFTPServer::wait_for_ack(&client_socket, block_count - 1, data_packet).await?;

            // If we've reached EOF, stop
            if num_read_from_file < MAX_DATA_SIZE {
                eprintln!("Finished handling read request");
                break;
            }
        }
        Ok(())
    }

    async fn wait_for_ack(
        client_socket: &UdpSocket,
        expected_block: u16,
        data_packet: &[u8],
    ) -> anyhow::Result<()> {
        let mut to_recv: TFTPBuffer = [0; MAX_DATA_PACKET_SIZE];

        let now = Instant::now();

        loop {
            let r = timeout(
                Duration::from_millis(3000),
                client_socket.recv(&mut to_recv),
            )
            .await;

            if r.is_err() {
                if now.elapsed().as_secs() >= MAX_ACK_TIMEOUT_SECS {
                    return Err(anyhow!("Timed out waiting for ACK"));
                }

                let num_written = client_socket.send(data_packet).await?;
                eprintln!("(Retry) Wrote {} bytes to socket", num_written);
                continue;
            }

            let recv_result = r.unwrap();
            let num_read_socket = recv_result?;

            let data = to_recv[0..num_read_socket].to_vec();

            let packet = TFTPPacket::try_from(data);
            if packet.is_err() {
                eprintln!(
                    "Received {} unparsable bytes: {:?}. Error: {}",
                    num_read_socket,
                    &to_recv[..num_read_socket],
                    packet.unwrap_err()
                );
                continue;
            }
            let packet = packet.unwrap();

            match packet {
                TFTPPacket::Ack(ackd_block) => {
                    if ackd_block == expected_block {
                        return Ok(());
                    } else {
                        eprintln!(
                            "Got ACK packet for block {} instead of {}",
                            ackd_block, expected_block
                        );
                    }
                }
                _ => {
                    eprintln!("Expected ACK packet, but got something else");
                    continue;
                }
            }
        }
    }
}

pub fn make_tftp_server<A: ToSocketAddrs>(addr: A) -> TFTPServer {
    TFTPServer {
        socket: block_on(UdpSocket::bind(addr)).unwrap(),
        buf: [0; MAX_DATA_PACKET_SIZE],
    }
}

fn main() {
    let mut server = make_tftp_server("0.0.0.0:69");

    let res = server.run();
    if res.is_err() {
        eprintln!("Server stopped with error: {:?}", res.err());
        std::process::exit(1);
    }
}
