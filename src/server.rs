use crate::packets::{TFTPMode, TFTPPacket, MAX_DATA_PACKET_SIZE, MAX_DATA_SIZE};
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
use std::convert::TryInto;
use std::string;
use std::time::{Duration, Instant};

const MAX_ACK_TIMEOUT_SECS: u64 = 10;

pub const ERROR_CODE_UNDEFINED: u16 = 0;
pub const ERROR_CODE_FILE_NOT_FOUND: u16 = 1;
pub const ERROR_CODE_ACCESS_VIOLATION: u16 = 2;
pub const ERROR_CODE_DISK_FULL: u16 = 3;
pub const ERROR_CODE_ILLEGAL_OP: u16 = 4;
pub const ERROR_CODE_UNKNOWN_TRANSFER: u16 = 5;
pub const ERROR_CODE_FILE_ALREADY_EXISTS: u16 = 6;
pub const ERROR_CODE_NO_SUCH_USER: u16 = 7;

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
        _mode: TFTPMode,
    ) -> anyhow::Result<()> {
        eprintln!("Time to handle a read request");

        let broadcast_addr = (Ipv4Addr::new(0, 0, 0, 0), 0);
        let client_socket = UdpSocket::bind(broadcast_addr).await?;
        client_socket.connect(remote).await?;

        let mut file = File::open(filename).await?;

        let mut block_count: u16 = 1;
        loop {
            let mut read_buf = vec![0; MAX_DATA_SIZE];
            let num_read_from_file = file.read(&mut read_buf).await?;
            read_buf.truncate(num_read_from_file);

            // TODO We have to convert our data if we're doing netascii mode!

            let data_packet = TFTPPacket::Data(block_count, read_buf);
            block_count += 1;

            // Write the data to our buddy
            let data_packet_bytes: Vec<u8> = data_packet.try_into()?;
            client_socket.send(&data_packet_bytes).await?;

            // Wait for ack, retransmitting as necessary
            TFTPServer::wait_for_ack(&client_socket, block_count - 1, &data_packet_bytes).await?;

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
