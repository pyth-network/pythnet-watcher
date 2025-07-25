//! This module defines the `PostedMessage` structure used to parse and verify messages
//! posted by the Wormhole protocol.
//!
//! ⚠️ Note: This is mostly a copy-paste from the Wormhole reference implementation.
//! If you forget how it works or need updates, refer to the official source:
//! https://github.com/wormhole-foundation/wormhole/blob/main/solana/bridge/program/src/accounts/posted_message.rs#
//!
//! Keep in sync if the upstream changes!

use {
    borsh::{BorshDeserialize, BorshSerialize},
    serde::{Deserialize, Serialize},
    std::{
        io::{Error, ErrorKind::InvalidData, Write},
        ops::{Deref, DerefMut},
    },
};

#[derive(Default, Debug, Clone, PartialEq)]
pub struct PostedMessageUnreliableData {
    pub message: MessageData,
}

#[derive(
    Debug, Default, BorshSerialize, BorshDeserialize, Clone, Serialize, Deserialize, PartialEq,
)]
pub struct MessageData {
    /// Header of the posted VAA
    pub vaa_version: u8,

    /// Level of consistency requested by the emitter
    pub consistency_level: u8,

    /// Time the vaa was submitted
    pub vaa_time: u32,

    /// Account where signatures are stored
    pub vaa_signature_account: [u8; 32],

    /// Time the posted message was created
    pub submission_time: u32,

    /// Unique nonce for this message
    pub nonce: u32,

    /// Sequence number of this message
    pub sequence: u64,

    /// Emitter of the message
    pub emitter_chain: u16,

    /// Emitter of the message
    pub emitter_address: [u8; 32],

    /// Message payload
    pub payload: Vec<u8>,
}

impl BorshSerialize for PostedMessageUnreliableData {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(b"msu")?;
        BorshSerialize::serialize(&self.message, writer)
    }
}

impl BorshDeserialize for PostedMessageUnreliableData {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        if buf.len() < 3 {
            return Err(Error::new(InvalidData, "Not enough bytes"));
        }

        let expected = b"msu";
        let magic: &[u8] = buf
            .get(0..3)
            .ok_or(Error::new(InvalidData, "Failed to get magic bytes"))?;
        if magic != expected {
            return Err(Error::new(
                InvalidData,
                format!(
                    "Magic mismatch. Expected {:?} but got {:?}",
                    expected, magic
                ),
            ));
        };
        *buf = buf
            .get(3..)
            .ok_or(Error::new(InvalidData, "Failed to get remaining bytes"))?;
        Ok(PostedMessageUnreliableData {
            message: <MessageData as BorshDeserialize>::deserialize(buf)?,
        })
    }
}

impl Deref for PostedMessageUnreliableData {
    type Target = MessageData;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for PostedMessageUnreliableData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_borsh_roundtrip() {
        let post_message_unreliable_data = PostedMessageUnreliableData {
            message: MessageData {
                vaa_version: 1,
                consistency_level: 2,
                vaa_time: 3,
                vaa_signature_account: [4u8; 32],
                submission_time: 5,
                nonce: 6,
                sequence: 7,
                emitter_chain: 8,
                emitter_address: [9u8; 32],
                payload: vec![10u8; 32],
            },
        };

        let encoded = borsh::to_vec(&post_message_unreliable_data).unwrap();

        let decoded = PostedMessageUnreliableData::try_from_slice(encoded.as_slice()).unwrap();
        assert_eq!(decoded, post_message_unreliable_data);
    }

    #[test]
    fn test_invalid_magic() {
        let post_message_unreliable_data = PostedMessageUnreliableData {
            message: MessageData {
                vaa_version: 1,
                consistency_level: 2,
                vaa_time: 3,
                vaa_signature_account: [4u8; 32],
                submission_time: 5,
                nonce: 6,
                sequence: 7,
                emitter_chain: 8,
                emitter_address: [9u8; 32],
                payload: vec![10u8; 32],
            },
        };

        let mut encoded = borsh::to_vec(&post_message_unreliable_data).unwrap();
        encoded[0..3].copy_from_slice(b"foo"); // Invalid magic

        let err = PostedMessageUnreliableData::try_from_slice(encoded.as_slice()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Magic mismatch. Expected [109, 115, 117] but got [102, 111, 111]"
        );
    }

    #[test]
    fn test_invalid_data_length() {
        let post_message_unreliable_data = PostedMessageUnreliableData {
            message: MessageData {
                vaa_version: 1,
                consistency_level: 2,
                vaa_time: 3,
                vaa_signature_account: [4u8; 32],
                submission_time: 5,
                nonce: 6,
                sequence: 7,
                emitter_chain: 8,
                emitter_address: [9u8; 32],
                payload: vec![10u8; 32],
            },
        };

        let mut encoded = borsh::to_vec(&post_message_unreliable_data).unwrap();
        encoded = encoded[0..encoded.len() - 1].to_vec();

        let err = PostedMessageUnreliableData::try_from_slice(encoded.as_slice()).unwrap_err();
        assert_eq!(err.to_string(), "Unexpected length of input");
    }
}
