//! CCSDS Space Packet Protocol framing (CCSDS 133.0-B-2).
//!
//! Lets an envelope travel inside the packet format that flight software
//! (NASA's core Flight System among it) and ground segments already speak.
//! Each envelope is the user data of one packet, or of a segmented sequence
//! (first / continuation / last) when it is larger than the mission's packet
//! size. The 6-octet primary header:
//!
//! ```text
//! | version (3) = 000 | type (1) | sec. hdr flag (1) | APID (11) |
//! | sequence flags (2) | packet sequence count (14)              |
//! | packet data length (16) = octets in data field − 1          |
//! ```
//!
//! interlingua adds end-to-end authentication and confidentiality above the
//! packet layer; CCSDS SDLS (355.0-B) protects frames on the space link
//! below it. The two are complementary.

use crate::cbor::Limits;
use crate::error::Error;

/// Primary header length in octets.
pub const PRIMARY_HEADER_LEN: usize = 6;
/// Largest packet data field.
pub const MAX_DATA_LEN: usize = 65_536;
/// Highest APID for user data (2047 is the idle APID).
pub const MAX_APID: u16 = 0x7fe;
/// The idle-packet APID.
pub const IDLE_APID: u16 = 0x7ff;
/// Packet sequence counts run modulo 2^14.
pub const SEQUENCE_MODULUS: u32 = 1 << 14;

/// Telemetry (reporting) or telecommand (requesting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Type bit 0.
    Telemetry,
    /// Type bit 1.
    Telecommand,
}

/// Position of a packet in a segmented user message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceFlags {
    /// `00`: a middle segment.
    Continuation,
    /// `01`: the first segment.
    First,
    /// `10`: the last segment.
    Last,
    /// `11`: a whole message in one packet.
    Unsegmented,
}

impl SequenceFlags {
    const fn bits(self) -> u16 {
        match self {
            Self::Continuation => 0b00,
            Self::First => 0b01,
            Self::Last => 0b10,
            Self::Unsegmented => 0b11,
        }
    }

    const fn from_bits(bits: u16) -> Self {
        match bits & 0b11 {
            0b00 => Self::Continuation,
            0b01 => Self::First,
            0b10 => Self::Last,
            _ => Self::Unsegmented,
        }
    }
}

/// One Space Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpacePacket {
    /// Telemetry or telecommand.
    pub packet_type: PacketType,
    /// Secondary header flag (the secondary header, if any, is in `data`).
    pub secondary_header: bool,
    /// Application process identifier, 0–2046.
    pub apid: u16,
    /// Segmentation position.
    pub flags: SequenceFlags,
    /// Packet sequence count, 0–16383.
    pub sequence_count: u16,
    /// Packet data field, 1–65536 octets.
    pub data: Vec<u8>,
}

impl SpacePacket {
    /// Encode the packet.
    ///
    /// # Errors
    /// [`Error::Ccsds`] for an out-of-range APID, count or data length.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.apid > MAX_APID {
            return Err(Error::Ccsds("APID must be 0-2046 (2047 is the idle APID)"));
        }
        if u32::from(self.sequence_count) >= SEQUENCE_MODULUS {
            return Err(Error::Ccsds("packet sequence count is 14 bits"));
        }
        let length = self
            .data
            .len()
            .checked_sub(1)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(Error::Ccsds("packet data field must be 1-65536 octets"))?;
        let type_bit = u16::from(self.packet_type == PacketType::Telecommand);
        let word1 = (type_bit << 12) | (u16::from(self.secondary_header) << 11) | self.apid;
        let word2 = (self.flags.bits() << 14) | self.sequence_count;
        let mut out = Vec::with_capacity(PRIMARY_HEADER_LEN + self.data.len());
        out.extend_from_slice(&word1.to_be_bytes());
        out.extend_from_slice(&word2.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decode the packet at the start of `bytes`; returns it and its length.
    ///
    /// # Errors
    /// [`Error::Ccsds`] for a short or truncated packet, a version other than
    /// 0, or an idle packet.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let header: [u8; PRIMARY_HEADER_LEN] = bytes
            .get(..PRIMARY_HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or(Error::Ccsds("shorter than a primary header"))?;
        let word1 = u16::from_be_bytes([header[0], header[1]]);
        let word2 = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::from(u16::from_be_bytes([header[4], header[5]])) + 1;
        if word1 >> 13 != 0 {
            return Err(Error::Ccsds("packet version number must be 0"));
        }
        let apid = word1 & 0x07ff;
        if apid == IDLE_APID {
            return Err(Error::Ccsds("idle packet (APID 2047) carries no user data"));
        }
        let total = PRIMARY_HEADER_LEN + length;
        let data = bytes
            .get(PRIMARY_HEADER_LEN..total)
            .ok_or(Error::Ccsds("packet is truncated"))?
            .to_vec();
        Ok((
            Self {
                packet_type: if word1 & 0x1000 == 0 {
                    PacketType::Telemetry
                } else {
                    PacketType::Telecommand
                },
                secondary_header: word1 & 0x0800 != 0,
                apid,
                flags: SequenceFlags::from_bits(word2 >> 14),
                sequence_count: word2 & 0x3fff,
                data,
            },
            total,
        ))
    }
}

/// Split `payload` into packets of at most `max_data` octets each, counting
/// from `first_count` (modulo 2^14).
///
/// # Errors
/// [`Error::Ccsds`] for an empty or oversized payload, or bad limits.
pub fn segment(
    apid: u16,
    packet_type: PacketType,
    first_count: u16,
    payload: &[u8],
    max_data: usize,
) -> Result<Vec<SpacePacket>, Error> {
    if !(1..=MAX_DATA_LEN).contains(&max_data) {
        return Err(Error::Ccsds("maximum data length must be 1-65536 octets"));
    }
    if payload.is_empty() {
        return Err(Error::Ccsds("nothing to frame"));
    }
    if payload.len() > Limits::DEFAULT.max_len {
        return Err(Error::Ccsds("payload is larger than 16 MiB"));
    }
    if u32::from(first_count) >= SEQUENCE_MODULUS {
        return Err(Error::Ccsds("packet sequence count is 14 bits"));
    }
    let count = payload.len().div_ceil(max_data);
    payload
        .chunks(max_data)
        .enumerate()
        .map(|(i, chunk)| {
            let flags = match (count, i) {
                (1, _) => SequenceFlags::Unsegmented,
                (_, 0) => SequenceFlags::First,
                (n, i) if i + 1 == n => SequenceFlags::Last,
                _ => SequenceFlags::Continuation,
            };
            let offset = u32::try_from(i % SEQUENCE_MODULUS as usize)
                .map_err(|_| Error::Ccsds("too many segments"))?;
            let sequence_count =
                u16::try_from((u32::from(first_count) + offset) % SEQUENCE_MODULUS)
                    .map_err(|_| Error::Ccsds("packet sequence count is 14 bits"))?;
            Ok(SpacePacket {
                packet_type,
                secondary_header: false,
                apid,
                flags,
                sequence_count,
                data: chunk.to_vec(),
            })
        })
        .collect()
}

/// Rebuilds user messages from packets of one APID, enforcing segment order
/// and sequence-count continuity inside each message, with a size bound.
#[derive(Debug)]
pub struct Reassembler {
    apid: u16,
    max_total: usize,
    buffer: Vec<u8>,
    next_count: u16,
    in_progress: bool,
}

impl Reassembler {
    /// A reassembler for `apid` accepting messages up to `max_total` octets.
    #[must_use]
    pub fn new(apid: u16, max_total: usize) -> Self {
        Self {
            apid,
            max_total,
            buffer: Vec::new(),
            next_count: 0,
            in_progress: false,
        }
    }

    fn fail(&mut self, why: &'static str) -> Error {
        self.buffer.clear();
        self.in_progress = false;
        Error::Ccsds(why)
    }

    /// Add a packet; returns a message when one completes.
    ///
    /// # Errors
    /// [`Error::Ccsds`] for a foreign APID, a gap or misordered segment, or an
    /// oversized message. The partial message is discarded.
    pub fn push(&mut self, packet: &SpacePacket) -> Result<Option<Vec<u8>>, Error> {
        if packet.apid != self.apid {
            return Err(Error::Ccsds("packet belongs to a different APID"));
        }
        if self.in_progress && packet.sequence_count != self.next_count {
            return Err(self.fail("sequence count gap: a segment was lost or reordered"));
        }
        self.next_count =
            u16::try_from((u32::from(packet.sequence_count) + 1) % SEQUENCE_MODULUS).unwrap_or(0);
        if self.buffer.len().saturating_add(packet.data.len()) > self.max_total {
            return Err(self.fail("reassembled message exceeds the size limit"));
        }
        match (packet.flags, self.in_progress) {
            (SequenceFlags::Unsegmented, false) => Ok(Some(packet.data.clone())),
            (SequenceFlags::First, false) => {
                self.buffer.extend_from_slice(&packet.data);
                self.in_progress = true;
                Ok(None)
            }
            (SequenceFlags::Continuation, true) => {
                self.buffer.extend_from_slice(&packet.data);
                Ok(None)
            }
            (SequenceFlags::Last, true) => {
                self.buffer.extend_from_slice(&packet.data);
                self.in_progress = false;
                Ok(Some(core::mem::take(&mut self.buffer)))
            }
            (SequenceFlags::Unsegmented | SequenceFlags::First, true) => {
                Err(self.fail("a new message started before the last segment"))
            }
            (SequenceFlags::Continuation | SequenceFlags::Last, false) => {
                Err(self.fail("a segment arrived without its first segment"))
            }
        }
    }
}

/// Encode a payload as concatenated packets.
///
/// # Errors
/// As [`segment`] and [`SpacePacket::encode`].
pub fn frame(
    apid: u16,
    packet_type: PacketType,
    first_count: u16,
    payload: &[u8],
    max_data: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for packet in segment(apid, packet_type, first_count, payload, max_data)? {
        out.extend_from_slice(&packet.encode()?);
    }
    Ok(out)
}

/// Decode concatenated packets that carry exactly one message.
///
/// # Errors
/// [`Error::Ccsds`] for malformed packets, mixed APIDs, gaps, or anything
/// other than exactly one complete message.
pub fn deframe(bytes: &[u8], max_total: usize) -> Result<Vec<u8>, Error> {
    let (first, _) = SpacePacket::decode(bytes)?;
    let mut reassembler = Reassembler::new(first.apid, max_total);
    let mut offset = 0;
    let mut message = None;
    while offset < bytes.len() {
        let (packet, used) = SpacePacket::decode(&bytes[offset..])?;
        offset += used;
        if message.is_some() {
            return Err(Error::Ccsds("packets continue after the message ended"));
        }
        message = reassembler.push(&packet)?;
    }
    message.ok_or(Error::Ccsds("the last segment is missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let p = SpacePacket {
            packet_type: PacketType::Telemetry,
            secondary_header: false,
            apid: 100,
            flags: SequenceFlags::Unsegmented,
            sequence_count: 0,
            data: vec![1, 2, 3, 4],
        };
        // 0064: version 0, telemetry, no secondary header, APID 100
        // c000: unsegmented, count 0 · 0003: four data octets − 1
        assert_eq!(
            crate::hex::encode(&p.encode().unwrap()),
            "0064c000000301020304"
        );
        assert_eq!(SpacePacket::decode(&p.encode().unwrap()).unwrap().0, p);
    }

    #[test]
    fn segmentation_round_trip_and_wrap() {
        let payload: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let wire = frame(0x7fe, PacketType::Telecommand, 16_382, &payload, 300).unwrap();
        assert_eq!(deframe(&wire, 4096).unwrap(), payload);
        let packets = segment(0x7fe, PacketType::Telecommand, 16_382, &payload, 300).unwrap();
        let counts: Vec<u16> = packets.iter().map(|p| p.sequence_count).collect();
        assert_eq!(counts, [16_382, 16_383, 0, 1]);
        assert!(deframe(&wire, 999).is_err(), "size limit");
        // Drop the second packet: the gap is detected.
        let first_len = PRIMARY_HEADER_LEN + 300;
        let gapped = [&wire[..first_len], &wire[2 * first_len..]].concat();
        assert!(deframe(&gapped, 4096).is_err());
    }

    #[test]
    fn rejects_bad_headers() {
        assert!(SpacePacket::decode(&crate::hex::decode("2064c000000301020304").unwrap()).is_err());
        assert!(SpacePacket::decode(&crate::hex::decode("07ffc000000301020304").unwrap()).is_err());
        assert!(SpacePacket::decode(&crate::hex::decode("0064c0000004010203").unwrap()).is_err());
    }
}
