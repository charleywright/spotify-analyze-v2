use std::{
    borrow::Cow,
    collections::VecDeque,
    fs::File,
    io::{self, Write},
    mem,
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{channel, Receiver, Sender},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::info;
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

use super::ProxyConfiguration;

#[derive(Debug, Clone, Copy)]
pub enum InterfaceDirection {
    Downstream,
    Upstream,
}
impl From<InterfaceDirection> for DataLink {
    fn from(value: InterfaceDirection) -> Self {
        match value {
            InterfaceDirection::Downstream => DataLink::USER0,
            InterfaceDirection::Upstream => DataLink::USER1,
        }
    }
}
pub type Interface = u32;
pub enum PacketDirection {
    Send,
    Recv,
}
impl PacketDirection {
    pub fn as_flag(&self) -> u32 {
        match self {
            PacketDirection::Send => 1 << 1, // Outbound
            PacketDirection::Recv => 1 << 0, // Inbound
        }
    }
}

pub struct PcapWriter {
    writer: PcapNgWriter<WiresharkWriter>,
    interface_counter: Interface,
}

impl PcapWriter {
    fn socket_addr_to_pcap(addr: &SocketAddr) -> InterfaceDescriptionOption {
        match addr {
            SocketAddr::V4(addr) => InterfaceDescriptionOption::IfIpv4Addr(Cow::Owned(Vec::from(addr.ip().octets()))),
            SocketAddr::V6(addr) => InterfaceDescriptionOption::IfIpv6Addr(Cow::Owned(Vec::from(addr.ip().octets()))),
        }
    }

    pub fn new(proxy_config: &ProxyConfiguration) -> anyhow::Result<Self> {
        let writer = WiresharkWriter::new(proxy_config)?;
        let section = SectionHeaderBlock {
            endianness: Endianness::native(),
            options: vec![SectionHeaderOption::UserApplication("Spotify Analyze V2 (Pineapple)".into())],
            ..Default::default()
        };
        Ok(PcapWriter { writer: PcapNgWriter::with_section_header(writer, section)?, interface_counter: 0 })
    }

    pub fn create_interface(&mut self, iface_type: InterfaceDirection, addr: SocketAddr) -> Interface {
        let options = match iface_type {
            InterfaceDirection::Downstream => vec![
                InterfaceDescriptionOption::IfName("pineapple-client-proxy".into()),
                InterfaceDescriptionOption::IfDescription("Pineapple's Proxy -> Client channel".into()),
                PcapWriter::socket_addr_to_pcap(&addr),
            ],
            InterfaceDirection::Upstream => vec![
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
        iface_idx
    }

    pub fn write_packet(&mut self, iface: Interface, direction: PacketDirection, data: Cow<[u8]>) {
        let data_len = data.len();
        let block = Block::EnhancedPacket(EnhancedPacketBlock {
            data,
            interface_id: iface,
            original_len: data_len as u32,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            options: vec![EnhancedPacketOption::Flags(direction.as_flag())],
        });
        self.writer.write_block(&block).expect("Failed to write data block");
    }
}

struct WiresharkWriter {
    buffer: Vec<u8>,
    pcap_file: Option<(VecDeque<u8>, File)>,
    fifo_tx: Sender<Vec<u8>>,
    fifo_thread: Option<JoinHandle<()>>,
}

impl WiresharkWriter {
    pub fn new(config: &ProxyConfiguration) -> anyhow::Result<Self> {
        let pcap_file = config.pcap_path.as_ref().map(File::create).transpose()?.map(|f| (VecDeque::new(), f));
        let (fifo_tx, fifo_rx) = channel();
        let fifo_path = config.fifo_path.clone();
        let fifo_thread =
            Some(thread::spawn(move || info!("FIFO: Thread complete {:?}", Self::fifo_thread(fifo_rx, fifo_path))));
        Ok(Self { buffer: Vec::new(), pcap_file, fifo_tx, fifo_thread })
    }

    #[cfg(target_os = "linux")]
    fn fifo_thread(rx: Receiver<Vec<u8>>, fifo_path: PathBuf) -> anyhow::Result<()> {
        use std::{os::unix::prelude::OpenOptionsExt, sync::mpsc::RecvTimeoutError};

        use inotify::{Inotify, WatchMask};
        use interprocess::os::unix::fifo_file;
        use log::trace;
        use nix::errno::Errno;

        if fifo_path.exists() {
            std::fs::remove_file(&fifo_path)?;
        }

        fifo_file::create_fifo(&fifo_path, 0o777)?;
        info!("FIFO: Created fifo at {fifo_path:?}");

        // Inotify lets us detect when Wireshark disconnects. The alternative is to try to write to the FIFO which
        // would fail if there are no readers however if Wireshark disconnects then reconnects before we write we would
        // miss the reconnect thus write a packet when Wireshark expects the PCAPNG header
        let mut inotify = Inotify::init()?;
        inotify.watches().add(&fifo_path, WatchMask::CLOSE_NOWRITE)?;
        let mut inotify_buffer = [0; 1024];

        let mut fifo_handle = None;
        let mut buffer = Vec::with_capacity(0x100000 /* 1MB */);
        let mut buffer_pos = 0;
        loop {
            // Check if we have been sent any data, if so add to the buffer
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(mut data) => buffer.append(&mut data),
                Err(err) => match err {
                    RecvTimeoutError::Timeout => {},
                    RecvTimeoutError::Disconnected => {
                        info!("FIFO: The other thread hung up");
                        break;
                    },
                },
            }

            // Try to open the FIFO for writing in a non-blocking way. If we fail there is nothing else to do
            let Some(file) = fifo_handle.as_mut() else {
                const O_NONBLOCK: i32 = 4000;
                match File::options().write(true).custom_flags(O_NONBLOCK).open(&fifo_path) {
                    Ok(f) => fifo_handle = Some(f),
                    Err(err) if let Some(os_err) = err.raw_os_error() => match Errno::from_raw(os_err) {
                        Errno::ENXIO => thread::sleep(Duration::from_millis(100)),
                        Errno::EINTR => {
                            info!("FIFO: open() was interrupted");
                            break;
                        },
                        _ => {
                            panic!("Failed to handle open() return code {err:?}");
                        },
                    },
                    Err(err) => {
                        return Err(err.into());
                    },
                }
                continue;
            };

            // We opened the FIFO, check if we have data to write to it
            let to_write = &buffer[buffer_pos..];
            if !to_write.is_empty() {
                match file.write(to_write) {
                    Ok(bytes_written) => {
                        trace!("FIFO: Wrote {} to FIFO", hex::encode(&to_write[0..bytes_written]));
                        buffer_pos += bytes_written;
                    },
                    Err(err) => {
                        // TODO: There should be a case when Wireshark disconnected and we try to write
                        info!("FIFO: Failed to write to fifo: {err:?}");
                        break;
                    },
                }
            }

            // Check if Wireshark disconnected without needing to write data (e.g. if we have nothing to write)
            match inotify.read_events(&mut inotify_buffer) {
                Ok(_events) => {
                    // Wireshark closed the file for reading
                    buffer_pos = 0;
                    fifo_handle = None;
                },
                Err(err) => match err.kind() {
                    io::ErrorKind::WouldBlock => {},
                    io::ErrorKind::Interrupted => {
                        info!("FIFO: Inotify read was interrupted");
                        break;
                    },
                    _ => {
                        info!("FIFO: Failed to get inotify events: {err:?}");
                        break;
                    },
                },
            }
        }

        info!("FIFO: Removing {fifo_path:?}");
        std::fs::remove_file(&fifo_path)?;
        info!("FIFO: All done");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn fifo_thread(rx: Receiver<Vec<u8>>, fifo_path: PathBuf) {
        unimplemented!("fifo_thread")
    }
}

impl Write for WiresharkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Try to write to a file if we are configured to do so
        if let Some((file_buffer, file)) = self.pcap_file.as_mut() {
            file_buffer.extend(buf);
            // TODO: This could be improved using VecDeque::as_slices() and good error checking
            let written = file.write(file_buffer.make_contiguous())?;
            file_buffer.drain(0..written);
        }

        // Write to the FIFO tunnel
        self.fifo_tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to send data to FIFO channel"))?;

        // Write to the in-memory buffer
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for WiresharkWriter {
    fn drop(&mut self) {
        let (mut tmp_tx, _) = channel::<Vec<u8>>();
        mem::swap(&mut self.fifo_tx, &mut tmp_tx);
        mem::drop(tmp_tx);
        thread::sleep(Duration::from_millis(100));
        if let Some(fifo_thread) = mem::take(&mut self.fifo_thread) {
            let _ = fifo_thread.join();
        }
    }
}
