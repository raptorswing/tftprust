use crate::errors::TFTPError;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::string::String;
use std::vec::Vec;

const OPCODE_READ_REQUEST: u16 = 1;
const OPCODE_WRITE_REQUEST: u16 = 2;
const OPCODE_DATA: u16 = 3;
const OPCODE_ACK: u16 = 4;
const OPCODE_ERROR: u16 = 5;

pub const MAX_DATA_SIZE: usize = 512;
pub const DATA_HEADER_SIZE: usize = 4;
pub const MAX_DATA_PACKET_SIZE: usize = MAX_DATA_SIZE + DATA_HEADER_SIZE;

const MODE_OCTET: &str = "octet";
const MODE_NETASCII: &str = "netascii";

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
    type Error = TFTPError;
    fn try_from(data: Vec<u8>) -> Result<Self, TFTPError> {
        if data.len() < 4 {
            return Err(TFTPError::MalformedPacket(
                "Not enough data for opcode + smallest packet".to_string(),
            ));
        }

        let opcode_bytes = data[..2]
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| TFTPError::GeneralError(e.into()))?;
        let opcode = u16::from_be_bytes(opcode_bytes);

        match opcode {
            // Read Request
            OPCODE_READ_REQUEST => {
                let (filename, mode) = extract_filename_and_mode(&data)?;
                Ok(TFTPPacket::ReadRequest(filename, mode))
            }
            // Write Request
            OPCODE_WRITE_REQUEST => {
                let (filename, mode) = extract_filename_and_mode(&data)?;
                Ok(TFTPPacket::WriteRequest(filename, mode))
            }
            // Data
            OPCODE_DATA => {
                // Extract the block number.
                let block_bytes =
                    data[..2]
                        .try_into()
                        .map_err(|e: std::array::TryFromSliceError| {
                            TFTPError::GeneralError(e.into())
                        })?;
                let block_number = u16::from_be_bytes(block_bytes);
                Ok(TFTPPacket::Data(block_number, data[4..].to_vec()))
            }
            // Ack
            OPCODE_ACK => {
                // There should only be four bytes
                if data.len() != 4 {
                    return Err(TFTPError::MalformedPacket(
                        "ACK packets must be exactly four bytes".to_string(),
                    ));
                }

                // Read the block number
                let block_num_array: [u8; 2] = [data[2], data[3]];
                let block_num = u16::from_be_bytes(block_num_array);
                Ok(TFTPPacket::Ack(block_num))
            }
            // Error
            OPCODE_ERROR => {
                // Extract the error code.
                let error_code_bytes =
                    data[..2]
                        .try_into()
                        .map_err(|e: std::array::TryFromSliceError| {
                            TFTPError::GeneralError(e.into())
                        })?;
                let error_code = u16::from_be_bytes(error_code_bytes);

                // Last byte must be null.
                if *data.last().unwrap() != 0 {
                    return Err(TFTPError::MalformedPacket(
                        "Error packet must end with NULL".to_string(),
                    ));
                }

                let error_msg = crate::netascii::decode(&data[4..data.len() - 1])?;

                Ok(TFTPPacket::Error(error_code, error_msg))
            }
            // WTF.
            _ => Err(TFTPError::MalformedPacket("Unknown opcode".to_string())),
        }
    }
}

impl TryFrom<TFTPPacket> for Vec<u8> {
    type Error = TFTPError;
    fn try_from(original: TFTPPacket) -> Result<Vec<u8>, TFTPError> {
        let mut a = Vec::with_capacity(MAX_DATA_PACKET_SIZE);

        // Closure that pushes a u16 to the vector in big-endian.
        let push_u16_be = |a: &mut Vec<u8>, number: u16| {
            let be_bytes = number.to_be_bytes();
            a.push(be_bytes[0]);
            a.push(be_bytes[1]);
        };

        // Closure that does stuff in common with the read and write requests.
        let read_write_common =
            |a: &mut Vec<u8>, filename: String, mode: TFTPMode| -> Result<(), TFTPError> {
                // Filename.
                let filename = crate::netascii::encode(filename)?;
                for x in filename.as_bytes() {
                    a.push(*x);
                }

                // Null byte after filename.
                a.push(0);

                // Write the mode.
                // We don't currently do netascii conversion here because the only modes we support are known
                // in advance to not need any conversion.
                let mode_str: &str = mode.into();
                for x in mode_str.as_bytes() {
                    a.push(*x);
                }

                // Null byte after mode.
                a.push(0);
                Ok(())
            };

        // First, write the opcode.
        match original {
            TFTPPacket::ReadRequest(filename, mode) => {
                push_u16_be(&mut a, OPCODE_READ_REQUEST);
                read_write_common(&mut a, filename, mode)?;
            }
            TFTPPacket::WriteRequest(filename, mode) => {
                push_u16_be(&mut a, OPCODE_WRITE_REQUEST);
                read_write_common(&mut a, filename, mode)?;
            }
            TFTPPacket::Data(block_num, mut data) => {
                push_u16_be(&mut a, OPCODE_DATA);
                push_u16_be(&mut a, block_num);
                a.append(&mut data);
            }
            TFTPPacket::Ack(block_num) => {
                push_u16_be(&mut a, OPCODE_ACK);
                push_u16_be(&mut a, block_num);
            }
            TFTPPacket::Error(error_code, error_string) => {
                push_u16_be(&mut a, OPCODE_ERROR);
                push_u16_be(&mut a, error_code);

                let error_string = crate::netascii::encode(error_string)?;
                for x in error_string.as_bytes() {
                    a.push(*x);
                }
            }
        };

        Ok(a)
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

fn extract_filename_and_mode(data: &Vec<u8>) -> Result<(String, TFTPMode), TFTPError> {
    // There should only be two null bytes total.
    {
        let num_nulls = data[2..data.len()].iter().filter(|&b| *b == 0).count();
        if num_nulls != 2 {
            return Err(TFTPError::MalformedPacket(
                "Unexpected number of nulls".to_string(),
            ));
        }
    }

    // Second null byte should be the last.
    let last_null_index = data.len() - 1;
    if data[last_null_index] != 0 {
        return Err(TFTPError::MalformedPacket(
            "Last byte of RRQ must be zero".to_string(),
        ));
    }

    let iter = data[..data.len()].iter();

    // Find first null byte.
    let first_null_index = iter.skip(2).position(|&b| b == 0);
    if first_null_index.is_none() {
        return Err(TFTPError::MalformedPacket(
            "Invalid RRQ - no first null byte".to_string(),
        ));
    }
    let first_null_index = first_null_index.unwrap() + 2;

    // Grab the filename.
    let filename = crate::netascii::decode(&data[2..first_null_index])?;
    let filename = filename.trim();
    if filename.is_empty() {
        return Err(TFTPError::MalformedPacket(
            "Filename must not be empty".to_string(),
        ));
    }

    // Grab the mode string.
    let mode = crate::netascii::decode(&data[first_null_index + 1..last_null_index])?;
    let mode = mode.to_ascii_lowercase();

    match mode.as_ref() {
        MODE_OCTET => Ok((filename.to_string(), TFTPMode::Octet)),
        MODE_NETASCII => Ok((filename.to_string(), TFTPMode::Ascii)),
        _ => Err(TFTPError::UnsupportedMode(mode)),
    }
}

impl From<TFTPMode> for &str {
    fn from(mode: TFTPMode) -> &'static str {
        match mode {
            TFTPMode::Octet => MODE_OCTET,
            TFTPMode::Ascii => MODE_NETASCII,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_too_short() {
        let packet = TFTPPacket::try_from(vec![]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_deserialize_invalid_opcode() {
        let packet = TFTPPacket::try_from(vec![0xff, 0xff, 0x00, 0x00]);
        assert!(packet.is_err());
    }
}
