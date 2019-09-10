extern crate ascii;
extern crate futures;
extern crate tokio;

use ascii::AsciiStr;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::string;
use tokio::fs::file;
use tokio::io;
use tokio::net::UdpSocket;
use tokio::prelude::*;

const MAX_DATA_SIZE : usize = 512;
const DATA_HEADER_SIZE : usize = 4;
const MAX_DATA_PACKET_SIZE : usize = MAX_DATA_SIZE + DATA_HEADER_SIZE;

enum TFTPMode {
    ASCII,
    Octet
}

enum TFTPPacket {
    ReadRequest(string::String, TFTPMode),
    WriteRequest(string::String, TFTPMode),
    Data(u16, Vec<u8>),
    Ack(u16),
    Error(u16, string::String)
}

impl TryFrom<([u8; MAX_DATA_PACKET_SIZE], usize)> for TFTPPacket {
    type Error = &'static str;

    fn try_from(value : ([u8; MAX_DATA_PACKET_SIZE], usize)) -> Result<Self, <TFTPPacket as TryFrom<([u8; MAX_DATA_PACKET_SIZE], usize)>>::Error> {
        let data = value.0;
        let length = value.1;

        if length < 4 {
            return Err("Not enough data for opcode + smallest packet");
        }

        let opcode_bytes = data[..2].try_into();
        if opcode_bytes.is_err() {
            return Err("Failed to convert slice to array somehow?");
        }
        let opcode = u16::from_be_bytes(opcode_bytes.unwrap());

        match opcode {
            // Read Request
            1 => {
                // There should only be two null bytes total
                {
                    let num_nulls : Vec<_> = data[2..length].iter().filter(|&b| *b == 0).collect();
                    if num_nulls.len() != 2 {
                        return Err("Unexpected number of nulls");
                    }
                }

                // Second null byte should be the last
                let last_null_index = length - 1;
                if data[last_null_index] != 0 {
                    return Err("Last byte of RRQ must be zero");
                }

                let iter = data[..length].iter();

                // Find first null byte
                let first_null_index = iter.skip(2).position(|&b| b == 0);
                if first_null_index.is_none() {
                    return Err("Invalid RRQ - no first null byte");
                }
                let first_null_index = first_null_index.unwrap() + 2;

                // Grab the filename
                let filename = AsciiStr::from_ascii(&data[2..first_null_index]);
                if filename.is_err() {
                    return Err("Invalid filename");
                }
                let filename = filename.unwrap().trim();
                if filename.len() <= 0 {
                    return Err("Filename must not be empty");
                }
                // TODO validate filename is legal filename characters?

                // Grab the mode string
                let mode = AsciiStr::from_ascii(&data[first_null_index + 1..last_null_index]);
                if mode.is_err() {
                    return Err("Invalid mode string");
                }
                let mode = mode.unwrap().to_ascii_lowercase();
                
                match mode.as_ref() {
                    "octet" => {
                        return Ok(TFTPPacket::ReadRequest(filename.to_string(), TFTPMode::Octet));
                    },
                    "netascii" => {
                        return Ok(TFTPPacket::ReadRequest(filename.to_string(), TFTPMode::ASCII));
                    },
                    _ => {
                        return Err("Invalid/unsupported mode");
                    }
                }
            },
            // Write Request
            2 => {

            },
            // Data
            3 => {

            },
            // Ack
            4 => {
                // There should only be four bytes
                if length != 4 {
                    return Err("ACK packets must be exactly four bytes");
                }

                // Read the block number
                let block_num_array : [u8; 2] = [data[2], data[3]];
                let block_num = u16::from_be_bytes(block_num_array);
                return Ok(TFTPPacket::Ack(block_num));
            },
            // Error
            5 => {

            },
            // WTF
            _ => {
                return Err("Unknown opcode");
            }
        }

        Ok(TFTPPacket::ReadRequest(String::from("asdf"), TFTPMode::Octet))
    }
}

impl std::fmt::Debug for TFTPPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TFTPPacket::ReadRequest(filename, mode) => write!(f, "ReadRequest('{}', {:?})", filename, mode),
            TFTPPacket::WriteRequest(_, _) => write!(f, "WriteRequest"),
            TFTPPacket::Data(_, _) => write!(f, "Data"),
            TFTPPacket::Ack(_) => write!(f, "Ack"),
            TFTPPacket::Error(_, _) => write!(f, "Error")
        }
    }
}

impl std::fmt::Debug for TFTPMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TFTPMode::ASCII => write!(f, "NetASCII"),
            TFTPMode::Octet => write!(f, "octet")
        }
    }
}

struct ReadTask {
    socket : UdpSocket,
    filename: string::String,
    block_count : u16,
    file : file::File,
    write_buffer : Option<[u8; MAX_DATA_PACKET_SIZE]>,
    write_bufer_size : usize,
    awaiting_ack : bool
}

impl Future for ReadTask {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        loop {
            if self.awaiting_ack {
                let mut to_recv : [u8; MAX_DATA_PACKET_SIZE] = [0; MAX_DATA_PACKET_SIZE];

                match self.socket.poll_recv_from(&mut to_recv) {
                    Ok(Async::Ready((num_read, sender))) => {
                        let packet = TFTPPacket::try_from((to_recv, num_read));
                        if packet.is_err() {
                            eprintln!("Received {} unparsable bytes from {:?}: {:?}. Error: {}", num_read, sender, &to_recv[..num_read], packet.unwrap_err());
                            continue;
                        }
                        let packet = packet.unwrap();

                        match packet {
                            TFTPPacket::Ack(ackd_block) => {
                                self.awaiting_ack = false;
                                if ackd_block != self.block_count - 1 {
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "ACK for unexpected block"));
                                }
                            },
                            _ => {
                                return Err(std::io::Error::new(std::io::ErrorKind::Other, "Expected ACK packet"));
                            }
                        }
                    },
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(err) => {
                        return Err(err);
                    }
                }
            }

            if self.write_buffer.is_none() {
                let mut to_send : [u8; MAX_DATA_PACKET_SIZE] = [0; MAX_DATA_PACKET_SIZE];
                to_send[1] = 3;

                let block_count_be_bytes = self.block_count.to_be_bytes();
                to_send[2] = block_count_be_bytes[0];
                to_send[3] = block_count_be_bytes[1];
                self.block_count += 1;

                match self.file.poll_read(&mut to_send[DATA_HEADER_SIZE..MAX_DATA_SIZE+DATA_HEADER_SIZE]) {
                    Ok(Async::Ready(num_read)) => {
                        println!("Read {} bytes from {}", num_read, self.filename);
                        if num_read <= 0 {
                            return Ok(Async::Ready(()));
                        }
                        self.write_buffer = Some(to_send);
                        self.write_bufer_size = num_read + DATA_HEADER_SIZE;
                    },
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(err) => {
                        eprintln!("Err during file read: {}", err);
                        return Err(err);
                    }
                }
            } else {
                match self.socket.poll_send(&self.write_buffer.unwrap()[..self.write_bufer_size]) {
                    Ok(Async::Ready(num_written)) => {
                        assert!(num_written == self.write_bufer_size, "Partial write on UDP socket shouldn't be possible");
                        self.write_buffer = None;
                        self.write_bufer_size = 0;
                        self.awaiting_ack = true;
                        println!("Wrote {} data bytes to socket", num_written);
                    },
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(err) => {
                        eprintln!("Err during socket write: {}", err);
                        return Err(err);
                    }
                }
            }
        }
    }
}

struct TFTPServer {
    socket: UdpSocket,
    buf: [u8; MAX_DATA_PACKET_SIZE],
}

impl Future for TFTPServer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            let (num_recv_bytes, sender) = match self.socket.poll_recv_from(&mut self.buf) {
                Ok(Async::Ready(val)) => val,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(err) => {
                    eprintln!("Err during recv: {}", err);
                    // TODO if datagram larger than BUF_SIZE is received, it never gets read successfully or discarded and we enter an infinite loop here...
                    // What is wrong with tokio where we can't just read an incomplete datagram? Windows-specific issue?
                    continue;
                }
            };

            println!("Received {} bytes from {:?}: {:?}", num_recv_bytes, sender, &self.buf[..num_recv_bytes]);

            let packet = TFTPPacket::try_from((self.buf, num_recv_bytes));
            if packet.is_err() {
                eprintln!("Received {} unparsable bytes from {:?}: {:?}. Error: {}", num_recv_bytes, sender, &self.buf[..num_recv_bytes], packet.unwrap_err());
                continue;
            }
            let packet = packet.unwrap();
            println!("Received {:?} from {:?}", packet, sender);

            match packet {
                TFTPPacket::ReadRequest(filename, mode) => {
                    let addr = "0.0.0.0:0".parse().unwrap();
                    let client_socket = UdpSocket::bind(&addr).unwrap();
                    client_socket.connect(&sender).unwrap();

                    let t = tokio::fs::File::open(filename.clone())
                        .and_then(|file| {
                            ReadTask{
                                socket: client_socket,
                                filename: filename,
                                block_count: 1,
                                file : file,
                                write_buffer: None,
                                write_bufer_size: 0,
                                awaiting_ack : false
                            }
                        });

                    tokio::spawn(t.map_err(|err| {eprintln!("Error in ReadRequest: {}", err)}));
                },
                _ => {
                    eprintln!("Unsupported op for now");
                    continue;
                }
            }
        }
    }
}

fn main() {
    let addr = "0.0.0.0:69".parse().unwrap();

    let server = TFTPServer {
        socket : UdpSocket::bind(&addr).unwrap(),
        buf: [0; MAX_DATA_PACKET_SIZE]
    };

    tokio::run(server.map_err(|err| {eprintln!("Error:{:?}", err)}));
}
