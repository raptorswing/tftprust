use anyhow::anyhow;
use ascii::AsciiStr;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::string::String;
use std::vec::Vec;

#[derive(PartialEq)]
pub enum TFTPMode {
    Ascii,
    Octet,
}

pub enum TFTPPacket {
    ReadRequest(String, TFTPMode),
    WriteRequest(String, TFTPMode),
    Data(u16, Vec<u8>),
    Ack(u16),
    Error(u16, String),
}

impl TryFrom<Vec<u8>> for TFTPPacket {
    type Error = anyhow::Error;
    fn try_from(data: Vec<u8>) -> anyhow::Result<Self> {
        if data.len() < 4 {
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
                    let num_nulls = data[2..data.len()].iter().filter(|&b| *b == 0).count();
                    if num_nulls != 2 {
                        return Err(anyhow!("Unexpected number of nulls"));
                    }
                }

                // Second null byte should be the last
                let last_null_index = data.len() - 1;
                if data[last_null_index] != 0 {
                    return Err(anyhow!("Last byte of RRQ must be zero"));
                }

                let iter = data[..data.len()].iter();

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
                            TFTPMode::Ascii,
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
                if data.len() != 4 {
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
            TFTPMode::Ascii => write!(f, "NetASCII"),
            TFTPMode::Octet => write!(f, "octet"),
        }
    }
}
