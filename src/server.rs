use crate::errors::TFTPError;
use crate::packets::{TFTPMode, TFTPPacket, MAX_DATA_PACKET_SIZE, MAX_DATA_SIZE};
use bytes::Bytes;
use futures_core::stream::Stream;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::string;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

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
    listen_addr: SocketAddr,
}

impl TFTPServer {
    pub fn new<T>(listen_addr: T) -> Result<TFTPServer, TFTPError>
    where
        T: ToSocketAddrs,
    {
        match listen_addr.to_socket_addrs()?.next() {
            Some(listen_addr) => {
                let std_socket = std::net::UdpSocket::bind(listen_addr)?;
                std_socket.set_nonblocking(true)?;
                let socket = UdpSocket::from_std(std_socket)?;
                Ok(TFTPServer {
                    socket,
                    listen_addr,
                })
            }
            None => Err(TFTPError::GeneralError(anyhow::anyhow!(
                "Failed to extract listen_addr"
            ))),
        }
    }

    pub async fn run(&self) -> Result<(), TFTPError> {
        let mut buf = [0; MAX_DATA_PACKET_SIZE];

        loop {
            let (num_recv_bytes, sender) = self.socket.recv_from(&mut buf).await?;
            let data = buf[0..num_recv_bytes].to_vec();

            let packet = TFTPPacket::try_from(data)?;

            let bind_addr = SocketAddr::new(self.listen_addr.ip(), 0);

            match packet {
                TFTPPacket::ReadRequest(filename, mode) => {
                    tokio::spawn(async move {
                        if let Err(e) =
                            TFTPServer::handle_read_request(bind_addr, sender, filename, mode).await
                        {
                            eprintln!("Error handling read request: {}", e);
                        }
                    });
                }
                TFTPPacket::WriteRequest(filename, mode) => {
                    tokio::spawn(async move {
                        if let Err(e) =
                            TFTPServer::handle_write_request(bind_addr, sender, filename, mode)
                                .await
                        {
                            eprintln!("Error handling write request: {}", e);
                        }
                    });
                }
                _ => {
                    eprintln!("Received unsupported packet {:?}", packet);
                }
            }
        }
    }

    async fn handle_read_request(
        bind_addr: SocketAddr,
        remote: SocketAddr,
        filename: string::String,
        mode: TFTPMode,
    ) -> Result<(), TFTPError> {
        eprintln!("Time to handle a read request");

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(remote).await?;

        let file = File::open(filename).await?;

        let mut stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
            Box::pin(tokio_util::io::ReaderStream::new(file));

        if mode == TFTPMode::Ascii {
            stream = Box::pin(crate::netascii::netascii_encode_stream(stream));
        }

        let mut reader = tokio_util::io::StreamReader::new(stream);

        let mut block_count: u16 = 1;
        loop {
            // TODO optimize to minimize allocations.
            let mut read_buf = vec![0; MAX_DATA_SIZE];
            let num_read_from_file = reader.read(&mut read_buf).await?;
            read_buf.truncate(num_read_from_file);

            let data_packet = TFTPPacket::Data(block_count, read_buf);
            block_count += 1;

            // Write the data to our buddy
            let data_packet_bytes: Vec<u8> = data_packet.try_into()?;
            socket.send(&data_packet_bytes).await?;

            // Wait for ack, retransmitting as necessary
            TFTPServer::wait_for_ack(&socket, block_count - 1, &data_packet_bytes).await?;

            // If we've reached EOF, stop
            if num_read_from_file < MAX_DATA_SIZE {
                eprintln!("Finished handling read request");
                break;
            }
        }
        Ok(())
    }

    async fn handle_write_request(
        bind_addr: SocketAddr,
        remote: SocketAddr,
        filename: String,
        _mode: TFTPMode, // TODO implement decode from netascii.
    ) -> Result<(), TFTPError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let bound_addr = socket.local_addr()?;
        socket.connect(remote).await?;

        eprintln!("Receiving file {} on {}", filename, bound_addr);
        let mut file = File::create(filename).await?;

        // Send initial ACK to get the ball rolling.
        TFTPServer::send_ack(&socket, 0).await?;

        let mut expected_block: u16 = 1;

        loop {
            let mut read_buf = vec![0; MAX_DATA_PACKET_SIZE];

            let r = timeout(Duration::from_millis(3000), socket.recv(&mut read_buf)).await;
            let num_read = match r {
                Err(_) => {
                    return Err(TFTPError::TimeoutError("waiting for data".to_string()));
                }
                Ok(recv_result) => match recv_result {
                    Err(e) => {
                        return Err(TFTPError::IOError(e));
                    }
                    Ok(num_read) => num_read,
                },
            };
            read_buf.truncate(num_read);

            let packet: TFTPPacket = read_buf.try_into()?;
            if let TFTPPacket::Data(block, data) = packet {
                if block != expected_block {
                    eprintln!("Got block {} but expected block {}", block, expected_block);
                    continue;
                }

                // Write data to file.
                // This is not cancellation-safe - see https://docs.rs/tokio/latest/tokio/io/trait.AsyncWriteExt.html#method.write_all.
                file.write_all(&data).await?;

                // Send ACK.
                TFTPServer::send_ack(&socket, block).await?;
                expected_block += 1;

                // We're done when the sender gives us less than MAX_DATA_SIZE bytes of data in a datagram.
                if data.len() < MAX_DATA_SIZE {
                    eprintln!("Finished receiving on {}", bound_addr);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn wait_for_ack(
        socket: &UdpSocket,
        expected_block: u16,
        data_packet: &[u8],
    ) -> Result<(), TFTPError> {
        let mut to_recv: TFTPBuffer = [0; MAX_DATA_PACKET_SIZE];

        let now = Instant::now();

        loop {
            let r = timeout(Duration::from_millis(3000), socket.recv(&mut to_recv)).await;

            let num_read = match r {
                Err(_) => {
                    if now.elapsed().as_secs() >= MAX_ACK_TIMEOUT_SECS {
                        return Err(TFTPError::TimeoutError("waiting for ACK".to_string()));
                    }
                    let num_written = socket.send(data_packet).await?;
                    eprintln!("(Retry) Wrote {} bytes to socket", num_written);
                    continue;
                }
                Ok(recv_result) => match recv_result {
                    Err(e) => {
                        return Err(TFTPError::IOError(e));
                    }
                    Ok(num_read) => num_read,
                },
            };

            let data = to_recv[0..num_read].to_vec();

            let packet = TFTPPacket::try_from(data);
            if let Err(e) = packet {
                eprintln!(
                    "Received {} unparsable bytes: {:?}. Error: {}",
                    num_read,
                    &to_recv[..num_read],
                    e
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

    async fn send_ack(socket: &UdpSocket, block: u16) -> Result<(), TFTPError> {
        let ack_bytes: Vec<u8> = TFTPPacket::Ack(block).try_into()?;
        let num_sent = socket.send(&ack_bytes).await?;
        if num_sent != ack_bytes.len() {
            return Err(TFTPError::GeneralError(anyhow::anyhow!(format!(
                "Expected to send {} bytes but only sent {}",
                ack_bytes.len(),
                num_sent
            ))));
        }
        Ok(())
    }
}
