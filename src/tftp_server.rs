extern crate ascii;
extern crate futures;

use anyhow::anyhow;
use ascii::AsciiStr;
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

const MAX_DATA_SIZE: usize = 512;
const DATA_HEADER_SIZE: usize = 4;
const MAX_DATA_PACKET_SIZE: usize = MAX_DATA_SIZE + DATA_HEADER_SIZE;

const MAX_ACK_TIMEOUT_SECS: u64 = 10;

type TFTPBuffer = [u8; MAX_DATA_PACKET_SIZE];

#[derive(PartialEq)]
enum TFTPMode {
    ASCII,
    Octet,
}

enum TFTPPacket {
    ReadRequest(string::String, TFTPMode),
    WriteRequest(string::String, TFTPMode),
    Data(u16, Vec<u8>),
    Ack(u16),
    Error(u16, string::String),
}

impl TryFrom<(TFTPBuffer, usize)> for TFTPPacket {
    type Error = anyhow::Error;
    fn try_from(value: (TFTPBuffer, usize)) -> anyhow::Result<Self> {
        let data = value.0;
        let length = value.1;

        if length < 4 {
            return Err(anyhow!("Not enough data for opcode + smallest packet"));
        }

        let opcode_bytes = data[..2].try_into();
        if opcode_bytes.is_err() {
            return Err(anyhow!("Failed to convert slice to array somehow?"));
        }
        let opcode = u16::from_be_bytes(opcode_bytes.unwrap());

        match opcode {
            // Read Request
            1 => {
                // There should only be two null bytes total
                {
                    let num_nulls: Vec<_> = data[2..length].iter().filter(|&b| *b == 0).collect();
                    if num_nulls.len() != 2 {
                        return Err(anyhow!("Unexpected number of nulls"));
                    }
                }

                // Second null byte should be the last
                let last_null_index = length - 1;
                if data[last_null_index] != 0 {
                    return Err(anyhow!("Last byte of RRQ must be zero"));
                }

                let iter = data[..length].iter();

                // Find first null byte
                let first_null_index = iter.skip(2).position(|&b| b == 0);
                if first_null_index.is_none() {
                    return Err(anyhow!("Invalid RRQ - no first null byte"));
                }
                let first_null_index = first_null_index.unwrap() + 2;

                // Grab the filename
                let filename = AsciiStr::from_ascii(&data[2..first_null_index]);
                if filename.is_err() {
                    return Err(anyhow!("Invalid filename"));
                }
                let filename = filename.unwrap().trim();
                if filename.is_empty() {
                    return Err(anyhow!("Filename must not be empty"));
                }
                // TODO validate filename is legal filename characters?

                // Grab the mode string
                let mode = AsciiStr::from_ascii(&data[first_null_index + 1..last_null_index]);
                if mode.is_err() {
                    return Err(anyhow!("Invalid mode string"));
                }
                let mode = mode.unwrap().to_ascii_lowercase();

                match mode.as_ref() {
                    "octet" => {
                        return Ok(TFTPPacket::ReadRequest(
                            filename.to_string(),
                            TFTPMode::Octet,
                        ));
                    }
                    "netascii" => {
                        return Ok(TFTPPacket::ReadRequest(
                            filename.to_string(),
                            TFTPMode::ASCII,
                        ));
                    }
                    _ => {
                        return Err(anyhow!("Invalid/unsupported mode"));
                    }
                }
            }
            // Write Request
            2 => {}
            // Data
            3 => {}
            // Ack
            4 => {
                // There should only be four bytes
                if length != 4 {
                    return Err(anyhow!("ACK packets must be exactly four bytes"));
                }

                // Read the block number
                let block_num_array: [u8; 2] = [data[2], data[3]];
                let block_num = u16::from_be_bytes(block_num_array);
                return Ok(TFTPPacket::Ack(block_num));
            }
            // Error
            5 => {}
            // WTF
            _ => {
                return Err(anyhow!("Unknown opcode"));
            }
        }

        Ok(TFTPPacket::ReadRequest(
            String::from("asdf"),
            TFTPMode::Octet,
        ))
    }
}

pub struct TFTPServer {
    socket: UdpSocket,
    buf: TFTPBuffer,
}

impl std::fmt::Debug for TFTPPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TFTPPacket::ReadRequest(filename, mode) => {
                write!(f, "ReadRequest('{}', {:?})", filename, mode)
            }
            TFTPPacket::WriteRequest(_, _) => write!(f, "WriteRequest"),
            TFTPPacket::Data(_, _) => write!(f, "Data"),
            TFTPPacket::Ack(_) => write!(f, "Ack"),
            TFTPPacket::Error(_, _) => write!(f, "Error"),
        }
    }
}

impl std::fmt::Debug for TFTPMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TFTPMode::ASCII => write!(f, "NetASCII"),
            TFTPMode::Octet => write!(f, "octet"),
        }
    }
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
        // println!("Received {} bytes from {:?}: {:?}", num_recv_bytes, sender, &self.buf[..num_recv_bytes]);

        // Parse bytes into packet
        let packet = TFTPPacket::try_from((self.buf, num_recv_bytes))?;

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

    async fn spawn_wrap<Fut>(future: Fut) -> ()
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

            let packet = TFTPPacket::try_from((to_recv, num_read_socket));
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
