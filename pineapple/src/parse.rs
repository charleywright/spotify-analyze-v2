use std::{collections::HashMap, path::PathBuf};

use anyhow::{anyhow, Context};
use clap::ArgMatches;
use pcap_file::{
    pcapng::{blocks::enhanced_packet::EnhancedPacketOption, Block, PcapNgParser},
    DataLink, PcapError,
};

use crate::pcap::{Interface, InterfaceDirection, PacketDirection};

pub fn launch_tui(args: &ArgMatches) -> anyhow::Result<()> {
    let file_path = args.get_one::<String>("file").unwrap();
    let file_path = PathBuf::from(file_path);

    if !file_path.exists() {
        return Err(anyhow!("Failed to read file: File not found"));
    }
    let file_contents = std::fs::read(&file_path)?;
    let capture = CaptureFile::from_slice(&file_contents)?;

    todo!("Display capture");

    Ok(())
}

struct CaptureFile {
    connections: Vec<CapturedConnection>,
}

impl CaptureFile {
    pub fn from_slice(input: &[u8]) -> anyhow::Result<Self> {
        // Parse the packet header
        let (mut input, mut parser) = PcapNgParser::new(input).context("Create PcapNG parser")?;

        // Pull out all blocks
        let mut blocks = Vec::new();
        'parse_blocks: loop {
            match parser.next_block(input) {
                Ok((remaining, block)) => {
                    blocks.push(block);
                    input = remaining;
                },
                Err(PcapError::IncompleteBuffer) => {
                    // We read the whole file, we're done
                    break 'parse_blocks;
                },
                Err(parse_error) => return Err(parse_error.into()),
            }
        }

        let mut connections = parser
            .interfaces()
            .iter()
            .enumerate()
            .filter_map(|(iface_idx, iface)| {
                let direction = match iface.linktype {
                    DataLink::USER0 => ConnectionDirection::Downstream,
                    DataLink::USER1 => ConnectionDirection::Upstream,
                    _ => return None,
                };
                let interface = iface_idx as Interface;
                let connection = CapturedConnection { direction, interface, packets: Vec::new() };
                Some((interface, connection))
            })
            .collect::<HashMap<_, _>>();

        for block in blocks {
            let Block::EnhancedPacket(packet) = block else {
                continue;
            };
            let direction = packet.options.iter().find_map(|option| {
                if let EnhancedPacketOption::Flags(flags) = option {
                    Some(PacketDirection::from_flag(*flags))
                } else {
                    None
                }
            });
            let Some(direction) = direction else {
                continue;
            };
            let Some(connection) = connections.get_mut(&packet.interface_id) else {
                continue;
            };
            connection.packets.push(CapturedPacket {
                direction,
                data: packet.data.to_vec(),
                formatted_string: FormattedString::NotAttempted,
            });
        }

        let mut connections = connections.into_values().collect::<Vec<_>>();
        connections.sort_by_key(|connection| connection.interface);

        Ok(Self { connections })
    }
}

type ConnectionDirection = InterfaceDirection;

struct CapturedConnection {
    direction: ConnectionDirection,
    interface: Interface,
    packets: Vec<CapturedPacket>,
}

struct CapturedPacket {
    direction: PacketDirection,
    data: Vec<u8>,
    formatted_string: FormattedString,
}

enum FormattedString {
    NotAttempted,
    Success(String),
    Failed(String),
}
