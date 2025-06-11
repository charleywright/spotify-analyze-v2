use anyhow::anyhow;
use pcap_file::DataLink;

#[derive(Debug, Clone, Copy)]
pub enum InterfaceDirection {
    /// Connected to the Spotify app
    Downstream,
    /// Connected to the Spotify AP
    Upstream,
}

impl From<InterfaceDirection> for DataLink {
    fn from(value: InterfaceDirection) -> Self {
        match value {
            InterfaceDirection::Downstream => Self::USER0,
            InterfaceDirection::Upstream => Self::USER1,
        }
    }
}

impl TryFrom<DataLink> for InterfaceDirection {
    type Error = anyhow::Error;

    fn try_from(value: DataLink) -> Result<Self, Self::Error> {
        match value {
            DataLink::USER0 => Ok(Self::Downstream),
            DataLink::USER1 => Ok(Self::Upstream),
            v => Err(anyhow!("Unexpected direction value: {v:?}")),
        }
    }
}

pub type Interface = u32;

pub enum PacketDirection {
    /// The packet was sent by the proxy
    Send,
    /// The packet was received by the proxy
    Recv,
}

impl PacketDirection {
    pub fn as_flag(&self) -> u32 {
        match self {
            PacketDirection::Send => 1 << 1, // Outbound
            PacketDirection::Recv => 1 << 0, // Inbound
        }
    }

    pub fn from_flag(flag: u32) -> Self {
        if flag & (1 << 1) > 0 {
            Self::Send
        } else {
            Self::Recv
        }
    }
}
