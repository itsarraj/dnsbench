use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    CAA = 257,
    ANY = 255,
}

impl RecordType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            12 => Some(RecordType::PTR),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            33 => Some(RecordType::SRV),
            257 => Some(RecordType::CAA),
            255 => Some(RecordType::ANY),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::PTR => "PTR",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::AAAA => "AAAA",
            RecordType::SRV => "SRV",
            RecordType::CAA => "CAA",
            RecordType::ANY => "ANY",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "NS" => Some(RecordType::NS),
            "CNAME" => Some(RecordType::CNAME),
            "SOA" => Some(RecordType::SOA),
            "PTR" => Some(RecordType::PTR),
            "MX" => Some(RecordType::MX),
            "TXT" => Some(RecordType::TXT),
            "AAAA" => Some(RecordType::AAAA),
            "SRV" => Some(RecordType::SRV),
            "CAA" => Some(RecordType::CAA),
            "ANY" => Some(RecordType::ANY),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError, // NXDOMAIN
    NotImplemented,
    Refused,
    Other(u8),
}

impl Rcode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            other => Rcode::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rcode::NoError => "NOERROR",
            Rcode::FormatError => "FORMERR",
            Rcode::ServerFailure => "SERVFAIL",
            Rcode::NameError => "NXDOMAIN",
            Rcode::NotImplemented => "NOTIMP",
            Rcode::Refused => "REFUSED",
            Rcode::Other(_) => "OTHER",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsResponse {
    pub id: u16,
    pub rcode: Rcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    pub answers: Vec<DnsRecord>,
}

pub fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return out;
    }

    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out
}

pub fn encode_dns_query(id: u16, domain: &str, qtype: RecordType, rd: bool) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // 1. Header (12 bytes)
    packet.extend_from_slice(&id.to_be_bytes()); // ID

    let mut flags = 0u16;
    if rd {
        flags |= 0x0100; // Recursion Desired
    }
    packet.extend_from_slice(&flags.to_be_bytes());

    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // 2. Question
    packet.extend(encode_domain_name(domain));
    packet.extend_from_slice(&qtype.to_u16().to_be_bytes()); // QTYPE
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = 1 (IN)

    packet
}

fn read_name(buf: &[u8], offset: &mut usize, depth: usize) -> Result<String> {
    if depth > 10 {
        bail!("Too many compression pointers in DNS packet");
    }

    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0;

    while *offset < buf.len() {
        let len = buf[*offset];
        if len == 0 {
            *offset += 1;
            break;
        }

        // Pointer: top two bits are set (0xC0)
        if (len & 0xC0) == 0xC0 {
            if *offset + 1 >= buf.len() {
                bail!("Truncated DNS compression pointer");
            }
            let pointer = (((len & 0x3F) as usize) << 8) | (buf[*offset + 1] as usize);
            if !jumped {
                jump_offset = *offset + 2;
                jumped = true;
            }

            let mut target_offset = pointer;
            let target_name = read_name(buf, &mut target_offset, depth + 1)?;
            labels.push(target_name);
            break;
        } else {
            *offset += 1;
            let end = *offset + len as usize;
            if end > buf.len() {
                bail!("Label extends beyond DNS packet length");
            }
            let label = std::str::from_utf8(&buf[*offset..end])
                .context("Non-UTF8 label in DNS name")?;
            labels.push(label.to_string());
            *offset = end;
        }
    }

    if jumped {
        *offset = jump_offset;
    }

    Ok(labels.join("."))
}

pub fn decode_dns_response(buf: &[u8]) -> Result<DnsResponse> {
    if buf.len() < 12 {
        bail!("DNS response packet too short (< 12 bytes)");
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);

    let qr = (flags & 0x8000) != 0;
    if !qr {
        bail!("Expected DNS response packet, received query");
    }

    let aa = (flags & 0x0400) != 0;
    let tc = (flags & 0x0200) != 0;
    let ra = (flags & 0x0080) != 0;
    let rcode = Rcode::from_u8((flags & 0x000F) as u8);

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;

    // Skip question section
    for _ in 0..qdcount {
        let _ = read_name(buf, &mut offset, 0)?;
        if offset + 4 > buf.len() {
            bail!("Truncated DNS question section");
        }
        offset += 4; // skip QTYPE (2) + QCLASS (2)
    }

    // Parse answers
    let mut answers = Vec::new();
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }

        let name = read_name(buf, &mut offset, 0)?;
        if offset + 10 > buf.len() {
            break;
        }

        let type_code = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _class_code = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        let rdata_bytes = &buf[offset..offset + rdlength];
        let mut rdata_offset = offset;

        let record_type_opt = RecordType::from_u16(type_code);
        let data_str = match record_type_opt {
            Some(RecordType::A) => {
                if rdlength == 4 {
                    let ip = Ipv4Addr::new(
                        rdata_bytes[0],
                        rdata_bytes[1],
                        rdata_bytes[2],
                        rdata_bytes[3],
                    );
                    ip.to_string()
                } else {
                    format!("<invalid A length {}>", rdlength)
                }
            }
            Some(RecordType::AAAA) => {
                if rdlength == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata_bytes);
                    let ip = Ipv6Addr::from(octets);
                    ip.to_string()
                } else {
                    format!("<invalid AAAA length {}>", rdlength)
                }
            }
            Some(RecordType::CNAME) | Some(RecordType::NS) | Some(RecordType::PTR) => {
                read_name(buf, &mut rdata_offset, 0).unwrap_or_else(|_| "<decompression error>".to_string())
            }
            Some(RecordType::MX) => {
                if rdlength >= 3 {
                    let pref = u16::from_be_bytes([rdata_bytes[0], rdata_bytes[1]]);
                    let mut mx_offset = offset + 2;
                    let exch = read_name(buf, &mut mx_offset, 0)
                        .unwrap_or_else(|_| "<invalid mx exchange>".to_string());
                    format!("{} {}", pref, exch)
                } else {
                    "<invalid MX>".to_string()
                }
            }
            Some(RecordType::TXT) => {
                let mut txts = Vec::new();
                let mut idx = 0;
                while idx < rdlength {
                    let str_len = rdata_bytes[idx] as usize;
                    idx += 1;
                    if idx + str_len <= rdlength {
                        let text = String::from_utf8_lossy(&rdata_bytes[idx..idx + str_len]);
                        txts.push(text.to_string());
                        idx += str_len;
                    } else {
                        break;
                    }
                }
                txts.join(" ")
            }
            _ => {
                // Unknown or unparsed: output hex string
                rdata_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("")
            }
        };

        offset += rdlength;

        if let Some(rtype) = record_type_opt {
            answers.push(DnsRecord {
                name,
                record_type: rtype,
                ttl,
                data: data_str,
            });
        }
    }

    Ok(DnsResponse {
        id,
        rcode,
        authoritative: aa,
        truncated: tc,
        recursion_available: ra,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name() {
        let encoded = encode_domain_name("google.com");
        assert_eq!(encoded, b"\x06google\x03com\x00");

        let encoded_root = encode_domain_name(".");
        assert_eq!(encoded_root, b"\x00");
    }

    #[test]
    fn test_encode_query() {
        let q = encode_dns_query(0x1234, "example.com", RecordType::A, true);
        assert_eq!(q[0..2], [0x12, 0x34]); // ID
        assert_eq!(q[2..4], [0x01, 0x00]); // Flags (RD = 1)
        assert_eq!(q[4..6], [0x00, 0x01]); // QDCOUNT = 1
        assert_eq!(&q[12..25], b"\x07example\x03com\x00");
        assert_eq!(&q[25..27], &[0x00, 0x01]); // Type A
        assert_eq!(&q[27..29], &[0x00, 0x01]); // Class IN
    }

    #[test]
    fn test_decode_a_response() {
        // Construct mock response for example.com A 93.184.216.34
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x12, 0x34]); // ID
        pkt.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, Rcode=0
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN

        // Answer: pointer to offset 12 (example.com)
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLength = 4
        pkt.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34

        let resp = decode_dns_response(&pkt).unwrap();
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.rcode, Rcode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].name, "example.com");
        assert_eq!(resp.answers[0].record_type, RecordType::A);
        assert_eq!(resp.answers[0].ttl, 300);
        assert_eq!(resp.answers[0].data, "93.184.216.34");
    }
}
