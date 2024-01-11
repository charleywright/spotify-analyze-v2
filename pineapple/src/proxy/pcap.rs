use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::EnhancedPacketBlock,
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
            section_header::{SectionHeaderBlock, SectionHeaderOption},
        },
        Block, PcapNgWriter,
    },
    DataLink, Endianness,
};
use std::{
    borrow::Cow,
    fs::File,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

pub enum IfaceType {
    DownstreamSend,
    DownstreamRecv,
    UpstreamSend,
    UpstreamRecv,
}

pub struct PcapWriter {
    writer: PcapNgWriter<File>,
    interface_counter: u32,
}

fn socket_addr_to_pcap(addr: &SocketAddr) -> InterfaceDescriptionOption {
    match addr {
        SocketAddr::V4(addr) => InterfaceDescriptionOption::IfIpv4Addr(Cow::Owned(Vec::from(addr.ip().octets()))),
        SocketAddr::V6(addr) => InterfaceDescriptionOption::IfIpv6Addr(Cow::Owned(Vec::from(addr.ip().octets()))),
    }
}

impl PcapWriter {
    pub fn new() -> Self {
        let file = File::create("output.pcapng").expect("Failed to open file");
        let section = SectionHeaderBlock {
            endianness: Endianness::Big,
            options: vec![SectionHeaderOption::UserApplication("Spotify Analyze V2 (Pineapple)".into())],
            ..Default::default()
        };
        PcapWriter {
            writer: PcapNgWriter::with_section_header(file, section).unwrap(),
            interface_counter: 0,
        }
    }

    pub fn create_interface(&mut self, iface_type: IfaceType, addr: SocketAddr) -> u32 {
        let linktype = match iface_type {
            IfaceType::DownstreamSend => DataLink::USER0,
            IfaceType::DownstreamRecv => DataLink::USER1,
            IfaceType::UpstreamSend => DataLink::USER2,
            IfaceType::UpstreamRecv => DataLink::USER3,
        };
        let options = match iface_type {
            IfaceType::DownstreamSend => {
                vec![
                    InterfaceDescriptionOption::IfName("pineapple-clientproxy-send".into()),
                    InterfaceDescriptionOption::IfDescription("Pineapple's Proxy -> Client channel".into()),
                    socket_addr_to_pcap(&addr),
                ]
            },
            IfaceType::DownstreamRecv => {
                vec![
                    InterfaceDescriptionOption::IfName("pineapple-clientproxy-recv".into()),
                    InterfaceDescriptionOption::IfDescription("Pineapple's Client -> Proxy channel".into()),
                    socket_addr_to_pcap(&addr),
                ]
            },
            IfaceType::UpstreamSend => {
                vec![
                    InterfaceDescriptionOption::IfName("pineapple-serverproxy-send".into()),
                    InterfaceDescriptionOption::IfDescription("Pineapple's Proxy -> Server channel".into()),
                    socket_addr_to_pcap(&addr),
                ]
            },
            IfaceType::UpstreamRecv => {
                vec![
                    InterfaceDescriptionOption::IfName("pineapple-serverproxy-recv".into()),
                    InterfaceDescriptionOption::IfDescription("Pineapple's Server -> Proxy channel".into()),
                    socket_addr_to_pcap(&addr),
                ]
            },
        };
        let block = Block::InterfaceDescription(InterfaceDescriptionBlock {
            linktype,
            snaplen: 0,
            options,
        });
        self.writer.write_block(&block).expect("Failed to write interface block");
        let iface_idx = self.interface_counter;
        self.interface_counter += 1;
        iface_idx
    }

    pub fn write_data(&mut self, iface_idx: u32, data: Cow<[u8]>) {
        let data_len = data.len();
        let block = Block::EnhancedPacket(EnhancedPacketBlock {
            data,
            interface_id: iface_idx,
            original_len: data_len as u32,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            options: vec![],
        });
        self.writer.write_block(&block).expect("Failed to write data block");
    }
}
