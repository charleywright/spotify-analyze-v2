use std::{
    borrow::Cow,
    fs::File,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
            section_header::{SectionHeaderBlock, SectionHeaderOption},
        },
        Block, PcapNgWriter,
    },
    DataLink, Endianness,
};

#[derive(Debug, Clone, Copy)]
pub enum InterfaceType {
    Downstream,
    Upstream,
}
impl InterfaceType {
    pub fn flags(&self) -> u32 {
        match self {
            InterfaceType::Downstream => 0 << 1,
            InterfaceType::Upstream => 1 << 1,
        }
    }
}
impl From<InterfaceType> for DataLink {
    fn from(value: InterfaceType) -> Self {
        match value {
            InterfaceType::Downstream => DataLink::USER0,
            InterfaceType::Upstream => DataLink::USER1,
        }
    }
}
#[derive(Debug)]
pub struct Interface {
    direction: InterfaceType,
    index: u32,
}
pub enum PacketDirection {
    Send,
    Recv,
}
impl PacketDirection {
    pub fn flags(&self) -> u32 {
        match self {
            PacketDirection::Send => 1,
            PacketDirection::Recv => 0,
        }
    }
}

pub struct PcapWriter {
    writer: PcapNgWriter<File>,
    interface_counter: u32,
}

impl PcapWriter {
    fn socket_addr_to_pcap(addr: &SocketAddr) -> InterfaceDescriptionOption {
        match addr {
            SocketAddr::V4(addr) => InterfaceDescriptionOption::IfIpv4Addr(Cow::Owned(Vec::from(addr.ip().octets()))),
            SocketAddr::V6(addr) => InterfaceDescriptionOption::IfIpv6Addr(Cow::Owned(Vec::from(addr.ip().octets()))),
        }
    }

    pub fn new() -> Self {
        let file = File::create("output.pcapng").expect("Failed to open file");
        let section = SectionHeaderBlock {
            endianness: Endianness::Big,
            options: vec![SectionHeaderOption::UserApplication("Spotify Analyze V2 (Pineapple)".into())],
            ..Default::default()
        };
        PcapWriter { writer: PcapNgWriter::with_section_header(file, section).unwrap(), interface_counter: 0 }
    }

    pub fn create_interface(&mut self, iface_type: InterfaceType, addr: SocketAddr) -> Interface {
        let options = match iface_type {
            InterfaceType::Downstream => vec![
                InterfaceDescriptionOption::IfName("pineapple-client-proxy".into()),
                InterfaceDescriptionOption::IfDescription("Pineapple's Proxy -> Client channel".into()),
                PcapWriter::socket_addr_to_pcap(&addr),
            ],
            InterfaceType::Upstream => vec![
                InterfaceDescriptionOption::IfName("pineapple-server-proxy".into()),
                InterfaceDescriptionOption::IfDescription("Pineapple's Proxy -> Server channel".into()),
                PcapWriter::socket_addr_to_pcap(&addr),
            ],
        };
        let block = Block::InterfaceDescription(InterfaceDescriptionBlock {
            linktype: DataLink::from(iface_type),
            snaplen: 0,
            options,
        });
        self.writer.write_block(&block).expect("Failed to write interface block");
        let iface_idx = self.interface_counter;
        self.interface_counter += 1;
        Interface { direction: iface_type, index: iface_idx }
    }

    pub fn write_packet(&mut self, iface: &Interface, direction: PacketDirection, data: Cow<[u8]>) {
        let data_len = data.len();
        let block = Block::EnhancedPacket(EnhancedPacketBlock {
            data,
            interface_id: iface.index,
            original_len: data_len as u32,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            options: vec![EnhancedPacketOption::Flags(direction.flags() | iface.direction.flags())],
        });
        self.writer.write_block(&block).expect("Failed to write data block");
    }
}
