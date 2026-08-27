//! Generate a deterministic DNS fixture pcap for offline Phase 12 demos.
//!
//! Usage: cargo run -q -p netagent-core --example gen_fixture -- <output.pcap>
//!
//! The fixture contains 10 NXDOMAIN and 5 NOERROR DNS responses from 10.0.0.8
//! to 1.1.1.1, which reliably triggers the NXDOMAIN spike rule
//! (ratio 0.67 > default 0.3 threshold, min_queries satisfied).

use std::path::PathBuf;

fn append_pcap_header(bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
}

fn append_pcap_packet(bytes: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    bytes.extend_from_slice(&ts_sec.to_le_bytes());
    bytes.extend_from_slice(&ts_usec.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(payload);
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn build_dns_payload(id: u16, flags: u16, qname: &str, answer_ip: Option<[u8; 4]>) -> Vec<u8> {
    let mut payload = Vec::new();
    let qname_bytes = encode_qname(qname);
    let answer_count = if answer_ip.is_some() { 1u16 } else { 0u16 };

    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&flags.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&answer_count.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&qname_bytes);
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());

    if let Some(ip) = answer_ip {
        payload.extend_from_slice(&[0xc0, 0x0c]);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&60u32.to_be_bytes());
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(&ip);
    }

    payload
}

fn build_udp_dns_frame(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    dns_payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    let total_length = (20 + 8 + dns_payload.len()) as u16;
    let mut ipv4 = vec![0u8; 20];
    ipv4[0] = 0x45;
    ipv4[1] = 0;
    ipv4[2..4].copy_from_slice(&total_length.to_be_bytes());
    ipv4[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    ipv4[6..8].copy_from_slice(&0u16.to_be_bytes());
    ipv4[8] = 64;
    ipv4[9] = 17;
    ipv4[12..16].copy_from_slice(&src_ip);
    ipv4[16..20].copy_from_slice(&dst_ip);
    let ip_checksum = checksum16(&ipv4);
    ipv4[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    frame.extend_from_slice(&ipv4);

    let udp_length = (8 + dns_payload.len()) as u16;
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_length.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(dns_payload);

    frame
}

fn main() {
    let output = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("examples/pcaps/dns_nxdomain_spike.pcap"));

    let mut bytes = Vec::new();
    append_pcap_header(&mut bytes);

    let src_ip = [10, 0, 0, 8];
    let dst_ip = [1, 1, 1, 1];
    let mut index = 0_u16;
    let mut timestamp = 1_717_777_800_u32;

    for _ in 0..10 {
        index += 1;
        let payload = build_dns_payload(
            0x2000 + index,
            0x8183,
            &format!("missing{index}.example"),
            None,
        );
        let frame = build_udp_dns_frame(src_ip, dst_ip, 53000 + index, 53, &payload);
        append_pcap_packet(&mut bytes, timestamp, 100_000, &frame);
        timestamp += 1;
    }
    for _ in 0..5 {
        index += 1;
        let payload = build_dns_payload(
            0x3000 + index,
            0x8180,
            &format!("ok{index}.example"),
            Some([93, 184, 216, 34]),
        );
        let frame = build_udp_dns_frame(src_ip, dst_ip, 54000 + index, 53, &payload);
        append_pcap_packet(&mut bytes, timestamp, 200_000, &frame);
        timestamp += 1;
    }

    if let Some(parent) = output.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&output, bytes).expect("write fixture pcap");
    eprintln!("fixture pcap written to {}", output.display());
}
