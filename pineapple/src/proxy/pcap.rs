use std::{
    borrow::Cow,
    collections::VecDeque,
    fs::File,
    io::{self, Write},
    mem,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender},
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

use super::HostConfiguration;

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
            SocketAddr::V4(addr) => {
                let ip = addr.ip().octets();
                let mask = [255, 255, 255, 255]; // We could query the OS for interfaces instead
                InterfaceDescriptionOption::IfIpv4Addr(Cow::Owned([ip, mask].concat()))
            },
            SocketAddr::V6(addr) => {
                let ip = addr.ip().octets();
                let mut buffer = Vec::from(ip);
                buffer.push(64);
                InterfaceDescriptionOption::IfIpv6Addr(Cow::Owned(buffer))
            },
        }
    }

    pub fn new(host_config: &HostConfiguration, pcap_path: Option<&Path>) -> anyhow::Result<Self> {
        let writer = WiresharkWriter::new(host_config, pcap_path)?;
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
    pub fn new(host_config: &HostConfiguration, pcap_path: Option<&Path>) -> anyhow::Result<Self> {
        let pcap_file = pcap_path.map(File::create).transpose()?.map(|f| (VecDeque::new(), f));
        let (fifo_tx, fifo_rx) = channel();
        let fifo_path = host_config.fifo_path();
        let fifo_thread =
            Some(thread::spawn(move || info!("FIFO: Thread complete {:?}", Self::fifo_thread(fifo_rx, fifo_path))));
        Ok(Self { buffer: Vec::new(), pcap_file, fifo_tx, fifo_thread })
    }

    const FIFO_BUFFER_INIT_SIZE: usize = 0x100000 /* 1MB */;

    #[cfg(target_os = "linux")]
    fn fifo_thread(rx: Receiver<Vec<u8>>, fifo_path: PathBuf) -> anyhow::Result<()> {
        use std::{io::ErrorKind, os::unix::prelude::OpenOptionsExt};

        use inotify::{Inotify, WatchMask};
        use interprocess::os::unix::fifo_file;
        use log::{debug, error, trace};
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
        let mut buffer = Vec::with_capacity(Self::FIFO_BUFFER_INIT_SIZE);
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
                            error!("FIFO: Failed to open file: {err:?}");
                            return Err(err.into());
                        },
                    },
                    Err(err) => {
                        error!("FIFO: Failed to open file: {err:?}");
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
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        // This can happen if we are receiving data and the user opens Wireshark
                        debug!("FIFO: Ignoring error while trying to write to fifo: {err:?}");
                    },
                    Err(err) => {
                        error!("FIFO: Failed to write to fifo: {err:?}");
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
    fn fifo_thread(rx: Receiver<Vec<u8>>, fifo_path: PathBuf) -> anyhow::Result<()> {
        use std::io::ErrorKind;

        use interprocess::os::windows::named_pipe::{pipe_mode, PipeListenerOptions, PipeStream};
        use log::{error, trace};
        use winapi::shared::winerror::ERROR_PIPE_LISTENING;

        struct ClientHandle {
            writer: PipeStream<pipe_mode::None, pipe_mode::Bytes>,
            buffer_pos: usize,
        }

        info!("FIFO: Creating server at {}", fifo_path.to_string_lossy());
        let listener =
            PipeListenerOptions::new().path(fifo_path).nonblocking(true).create_send_only::<pipe_mode::Bytes>()?;
        info!("FIFO: Created FIFO listener");

        let mut buffer = Vec::with_capacity(Self::FIFO_BUFFER_INIT_SIZE);
        // If we close one handle and open a new one before the next attempt to write, we will miss the disconnection.
        // On Linux we use inotify to detect when the reader closes the file, we can't do this on Windows. Instead we
        // allow more than one client to be opened then detect the disconnect on the next write.
        let mut clients: [Option<ClientHandle>; 5] = Default::default();
        loop {
            for client_handle in clients.iter_mut() {
                if let Some(client) = client_handle.as_mut() {
                    let to_write = &buffer[client.buffer_pos..];
                    if to_write.is_empty() {
                        continue;
                    }
                    match client.writer.write(to_write) {
                        Ok(bytes_written) => {
                            trace!("FIFO: Wrote {} to FIFO", hex::encode(&to_write[0..bytes_written]));
                            client.buffer_pos += bytes_written;
                            continue;
                        },
                        Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                        Err(err) if err.kind() == ErrorKind::BrokenPipe => {
                            info!("FIFO: Disconnected from client");
                        },
                        Err(err) => {
                            error!("FIFO: Failed to write to fifo: {err:?}");
                        },
                    };
                    // If we reach here, remove the client from our list
                    info!("FIFO: Client got disconnected");
                    let _ = std::mem::take(client_handle);
                }
            }

            // Check if we have been sent any data, if so add to the buffer
            match rx.recv_timeout(Duration::from_millis(1)) {
                Ok(mut data) => buffer.append(&mut data),
                Err(err) => match err {
                    RecvTimeoutError::Timeout => {},
                    RecvTimeoutError::Disconnected => {
                        info!("FIFO: The other thread hung up");
                        break;
                    },
                },
            }

            // Check if a new client has tried to connect
            for client in clients.iter_mut() {
                if client.is_none() {
                    match listener.accept() {
                        Ok(stream) => {
                            info!("FIFO: Accepted new client");
                            *client = Some(ClientHandle { writer: stream, buffer_pos: 0 });
                        },
                        Err(err) if let Some(os_err) = err.raw_os_error() => match os_err as u32 {
                            ERROR_PIPE_LISTENING => {},
                            _ => {
                                error!("FIFO: Failed to handle os error when accepting a client: {err:?}");
                                return Err(err.into());
                            },
                        },
                        Err(err) => {
                            info!("FIFO: Got error while accepting fifo {err:?}");
                            return Err(err.into());
                        },
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn fifo_thread(rx: Receiver<Vec<u8>>, _fifo_path: PathBuf) -> anyhow::Result<()> {
        use log::warn;

        // TODO: How do we detect when Wireshark disconnects?
        //       If we write a packet to the FIFO then Wireshark disconnects and reconnects, we have no way of knowing.
        //       This is a problem because Wireshark will now be expecting the PCAP[NG] header but we think we're
        //       already connected so we send the next data packet, causing Wireshark to error. On Linux we use inotify
        //       which tells us when a process closes a handle for reading. Windows allows multiple clients so we don't
        //       have this problem
        warn!("Wireshark live updates are not supported on MacOS");
        let _ = Self::FIFO_BUFFER_INIT_SIZE;

        loop {
            match rx.recv_timeout(Duration::from_millis(1)) {
                Ok(_data) => {},
                Err(err) => match err {
                    RecvTimeoutError::Timeout => {},
                    RecvTimeoutError::Disconnected => {
                        info!("FIFO: The other thread hung up");
                        break;
                    },
                },
            }
        }

        Ok(())
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
        self.fifo_tx.send(buf.to_vec()).map_err(|_| io::Error::other("Failed to send data to FIFO channel"))?;

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
