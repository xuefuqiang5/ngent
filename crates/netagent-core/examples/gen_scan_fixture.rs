//! Generate a deterministic TCP SYN-scan fixture pcap for offline Phase 17
//! demos and sensor-connector verification.
//!
//! Usage: cargo run -q -p netagent-core --example gen_scan_fixture -- <output.pcap>
//!
//! The fixture contains raw TCP SYN packets from 10.0.0.9 to many distinct
//! ports of 192.168.1.10, which reliably triggers the Zeek conn_state S0
//! SYN-scan analyzer and may match Suricata scan rules.

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

/// Build an Ethernet/IPv4/TCP SYN frame with a correct TCP checksum.
fn build_syn_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    let mut ipv4 = vec![0u8; 20];
    ipv4[0] = 0x45;
    ipv4[1] = 0;
    ipv4[2..4].copy_from_slice(&40u16.to_be_bytes());
    ipv4[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    ipv4[6..8].copy_from_slice(&0u16.to_be_bytes());
    ipv4[8] = 64;
    ipv4[9] = 6;
    ipv4[12..16].copy_from_slice(&src_ip);
    ipv4[16..20].copy_from_slice(&dst_ip);
    let ip_checksum = checksum16(&ipv4);
    ipv4[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    frame.extend_from_slice(&ipv4);

    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
    tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());

    let pseudo = {
        let mut data = Vec::new();
        data.extend_from_slice(&src_ip);
        data.extend_from_slice(&dst_ip);
        data.push(0);
        data.push(6);
        data.extend_from_slice(&(20u16).to_be_bytes());
        data.extend_from_slice(&tcp);
        data
    };
    let tcp_checksum = checksum16(&pseudo);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    frame.extend_from_slice(&tcp);

    frame
}

fn main() {
    let output = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("examples/pcaps/tcp_syn_scan.pcap"));

    let mut bytes = Vec::new();
    append_pcap_header(&mut bytes);

    let src_ip = [10, 0, 0, 9];
    let dst_ip = [192, 168, 1, 10];
    for (timestamp, index) in (1_717_778_000_u32..).zip(0..12) {
        let port = 40000 + index;
        let frame = build_syn_frame(src_ip, dst_ip, 51000 + index, port);
        append_pcap_packet(&mut bytes, timestamp, 100_000, &frame);
    }

    if let Some(parent) = output.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&output, bytes).expect("write scan fixture pcap");
    eprintln!("scan fixture pcap written to {}", output.display());
}
