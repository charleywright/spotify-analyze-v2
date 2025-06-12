use std::{collections::HashMap, ops::Deref, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context};
use bytes::{Buf, Bytes};
use clap::ArgMatches;
use count_digits::CountDigits;
use crossterm::event::{self, Event, KeyCode};
use num_enum::FromPrimitive;
use pcap_file::{
    pcapng::{
        self,
        blocks::{enhanced_packet::EnhancedPacketOption, interface_description::InterfaceDescriptionOption},
        PcapNgParser,
    },
    DataLink, PcapError,
};
use pretty::DocBuilder;
use protobuf::Message;
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
    Frame,
};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    pcap::{Interface, InterfaceDirection, PacketDirection},
    proto::{keyexchange_old, mercury_old},
};

pub fn launch_tui(args: &ArgMatches) -> anyhow::Result<()> {
    let file_path = args.get_one::<String>("file").unwrap();
    let file_path = PathBuf::from(file_path);

    if !file_path.exists() {
        return Err(anyhow!("Failed to read file: File not found"));
    }
    let file_contents = std::fs::read(&file_path)?;
    let mut capture = CaptureFile::from_slice(&file_contents)?;

    let mut status_bar = StatusBar::new(&capture);
    let mut terminal = ratatui::init();
    'render_loop: loop {
        if status_bar.should_quit {
            break 'render_loop;
        }

        terminal
            .draw(|frame| {
                use Constraint::{Length, Min};

                let vertical = Layout::vertical([Min(1), Length(2)]);
                let [capture_container, status_bar_area] = vertical.areas(frame.area());
                capture.render(frame, capture_container);
                status_bar.set_status(capture.get_status());
                status_bar.render(frame, status_bar_area);
            })
            .expect("Failed to draw frame");

        let event = event::read().expect("Failed to read event");
        if status_bar.handle_event(&event) == HandleEventResult::Consumed {
            continue;
        }
        capture.handle_event(&event);
    }
    ratatui::restore();

    Ok(())
}

trait Renderable {
    fn render(&mut self, frame: &mut Frame<'_>, area: Rect);

    fn handle_event(&mut self, event: &Event) -> HandleEventResult;
}

#[derive(PartialEq, Eq)]
enum HandleEventResult {
    Ignored,
    Consumed,
}

struct StatusBar {
    help_text: Line<'static>,
    capture_summary: Line<'static>,
    capture_summary_width: u16,
    status: String,
    should_quit: bool,
}

impl StatusBar {
    fn new(capture: &CaptureFile) -> Self {
        let help_text = Line::from(vec![
            "q".bold(),
            " to quit | ".into(),
            "Enter".bold(),
            " to select | ".into(),
            "Backspace".bold(),
            " to deselect | ".into(),
            "Arrow[Up|Down]".bold(),
            " to navigate".into(),
        ])
        .fg(Color::White)
        .bg(Color::DarkGray);

        let connection_count = capture.connections.len().to_string();
        let packet_count =
            capture.connections.iter().map(|connection| connection.packets.len()).sum::<usize>().to_string();
        let capture_summary_width = (connection_count.len() + 15 + packet_count.len() + 8) as u16;
        let capture_summary =
            Line::from(vec![connection_count.bold(), " connections | ".into(), packet_count.bold(), " packets".into()])
                .fg(Color::White)
                .bg(Color::DarkGray);

        Self { help_text, capture_summary, capture_summary_width, status: String::new(), should_quit: false }
    }

    fn set_status(&mut self, new_status: String) {
        self.status = new_status;
    }
}

impl Renderable for StatusBar {
    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use Constraint::{Fill, Length};

        let vertical = Layout::vertical([Length(1), Length(1)]);
        let [status_area, details_area] = vertical.areas(area);
        frame.render_widget(Line::from(self.status.as_str()).fg(Color::White).bg(Color::DarkGray), status_area);
        let horizontal = Layout::horizontal([Fill(1), Length(self.capture_summary_width)]);
        let [help_text_area, summary_area] = horizontal.areas(details_area);
        frame.render_widget(&self.help_text, help_text_area);
        frame.render_widget(&self.capture_summary, summary_area);
    }

    fn handle_event(&mut self, event: &Event) -> HandleEventResult {
        if let Event::Key(key_event) = event {
            if key_event.code == KeyCode::Char('q') {
                self.should_quit = true;
                return HandleEventResult::Consumed;
            }
        }
        HandleEventResult::Ignored
    }
}

struct CaptureFile {
    connections: Vec<CapturedConnection>,

    connection_state: TableState,
    connection_scroll_state: ScrollbarState,
    active_connection_index: Option<usize>,

    packet_state: TableState,
    packet_scroll_state: ScrollbarState,
    active_packet_index: Option<usize>,
}

impl CaptureFile {
    fn from_slice(input: &[u8]) -> anyhow::Result<Self> {
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
                let description = iface.options.iter().find_map(|option| {
                    if let InterfaceDescriptionOption::IfDescription(description) = option {
                        Some(description.to_string())
                    } else {
                        None
                    }
                })?;
                let interface = iface_idx as Interface;
                let connection = CapturedConnection { direction, interface, description, packets: Vec::new() };
                Some((interface, connection))
            })
            .collect::<HashMap<_, _>>();

        for block in blocks {
            let pcapng::Block::EnhancedPacket(packet) = block else {
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
            let data = Bytes::from(packet.data.to_vec());
            connection.packets.push(CapturedPacket {
                direction,
                data: data.clone(),
                packet_type: None,
                packet_len: None,
                short_string: None,
                details_formatter: PacketFormatter::Hex(data),
            });
        }

        let mut connections = connections.into_values().collect::<Vec<_>>();
        connections.sort_by_key(|connection| connection.interface);
        let connection_count = connections.len();

        Ok(Self {
            connections,

            connection_state: TableState::new().with_selected(0),
            connection_scroll_state: ScrollbarState::new(connection_count),
            active_connection_index: None,

            packet_state: TableState::new(),
            packet_scroll_state: ScrollbarState::new(0),
            active_packet_index: None,
        })
    }

    fn previous(&mut self) {
        if let Some(connection_index) = self.active_connection_index {
            let i = match self.packet_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.connections[connection_index].packets.len().saturating_sub(1)
                    } else {
                        i - 1
                    }
                },
                None => 0,
            };
            self.packet_state.select(Some(i));
            self.packet_scroll_state = self.packet_scroll_state.position(i);
        } else {
            let i = match self.connection_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.connections.len().saturating_sub(1)
                    } else {
                        i - 1
                    }
                },
                None => 0,
            };
            self.connection_state.select(Some(i));
            self.connection_scroll_state = self.connection_scroll_state.position(i);
        }
    }

    fn next(&mut self) {
        if let Some(connection_index) = self.active_connection_index {
            let connection = &self.connections[connection_index];
            let i = match self.packet_state.selected() {
                Some(i) => {
                    if i >= connection.packets.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                },
                None => 0,
            };
            self.packet_state.select(Some(i));
            self.packet_scroll_state = self.packet_scroll_state.position(i);
        } else {
            let i = match self.connection_state.selected() {
                Some(i) => {
                    if i >= self.connections.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                },
                None => 0,
            };
            self.connection_state.select(Some(i));
            self.connection_scroll_state = self.connection_scroll_state.position(i);
        }
    }

    fn select(&mut self) {
        if self.active_connection_index.is_some() {
            if let Some(idx) = self.packet_state.selected() {
                self.active_packet_index = Some(idx);
            }
        } else if let Some(idx) = self.connection_state.selected() {
            self.active_connection_index = Some(idx);
            let connection = &self.connections[idx];
            self.packet_state.select(Some(0));
            self.packet_scroll_state = self.packet_scroll_state.content_length(connection.packets.len()).position(0);
        }
    }

    fn unselect(&mut self) {
        if self.active_packet_index.is_some() {
            self.active_packet_index = None;
        } else {
            self.active_connection_index = None;
        }
    }

    fn get_status(&self) -> String {
        match self.active_connection_index {
            Some(connection_idx) => {
                let connection = &self.connections[connection_idx];
                format!(
                    "Viewing {} connection {connection_idx} with {} packets",
                    connection.direction.as_str(),
                    connection.packets.len()
                )
            },
            None => "Select a connection".to_owned(),
        }
    }
}

impl Renderable for CaptureFile {
    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        if let Some(connection_index) = self.active_connection_index {
            let vertical = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Fill(if self.active_packet_index.is_some() {
                    3
                } else {
                    0
                }),
            ]);
            let [packet_list_area, packet_details_area] = vertical.areas(area);
            let horizontal = Layout::horizontal([Constraint::Fill(1), Constraint::Length(3)]);
            let [packet_list_area, packet_list_scroll_area] = horizontal.areas(packet_list_area);

            let connection = &mut self.connections[connection_index];
            let packet_count = connection.packets.len();
            let largest_packet_len = connection
                .packets
                .iter_mut()
                .map(|p| {
                    p.try_parse(connection.direction);
                    p.packet_len.unwrap_or(0)
                })
                .max()
                .unwrap_or(0);
            let header = ["Id".bold(), "Direction".bold(), "Type".bold(), "Length".bold(), "Details".bold()]
                .into_iter()
                .map(Cell::from)
                .collect::<Row>()
                .height(1);
            let rows = connection
                .packets
                .iter_mut()
                .enumerate()
                .map(|(i, packet)| {
                    if packet.packet_type.is_none() {
                        packet.try_parse(connection.direction);
                    }
                    [
                        i.to_string().into(),
                        packet.direction.as_span(),
                        packet.packet_type.as_ref().unwrap_or(&PacketType::None).to_string().into(),
                        packet.packet_len.as_ref().map(u16::to_string).unwrap_or("Unknown".to_owned()).into(),
                        packet.short_string.as_deref().unwrap_or("Missing details").into(),
                    ]
                    .into_iter()
                    .map(Cell::from)
                    .collect::<Row>()
                })
                .collect::<Vec<_>>();
            let table = Table::new(rows, [
                Constraint::Length(std::cmp::max(packet_count.count_digits() as u16 + 1, 5)),
                Constraint::Length(10),
                Constraint::Length(24),
                Constraint::Length(std::cmp::max(largest_packet_len.count_digits() as u16 + 1, 7)),
                Constraint::Fill(1),
            ])
            .header(header)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_stateful_widget(table, packet_list_area, &mut self.packet_state);

            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None);
            frame.render_stateful_widget(
                scrollbar,
                packet_list_scroll_area.inner(Margin { vertical: 1, horizontal: 1 }),
                &mut self.packet_scroll_state,
            );

            if let Some(packet_index) = self.active_packet_index {
                let packet = &connection.packets[packet_index];
                packet.details_formatter.render(frame, packet_details_area);
            }
        } else {
            let header = ["Id".bold(), "Direction".bold(), "# Packets".bold(), "Description".bold()]
                .into_iter()
                .map(Cell::from)
                .collect::<Row>()
                .height(1);
            let rows = self
                .connections
                .iter()
                .enumerate()
                .map(|(i, conn)| {
                    [
                        i.to_string().into(),
                        conn.direction.as_span(),
                        conn.packets.len().to_string().into(),
                        Span::from(&conn.description),
                    ]
                    .into_iter()
                    .map(Cell::from)
                    .collect::<Row>()
                })
                .collect::<Vec<_>>();
            let table = Table::new(rows, [
                Constraint::Length(std::cmp::max(self.connections.len().count_digits() as u16 + 1, 5)),
                Constraint::Length(11),
                Constraint::Length(std::cmp::max(
                    self.connections.iter().map(|conn| conn.packets.len()).max().unwrap_or(0).count_digits() as u16 + 1,
                    10,
                )),
                Constraint::Fill(1),
            ])
            .header(header)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_stateful_widget(table, area, &mut self.connection_state);

            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None);
            frame.render_stateful_widget(
                scrollbar,
                area.inner(Margin { vertical: 1, horizontal: 1 }),
                &mut self.connection_scroll_state,
            );
        }
    }

    fn handle_event(&mut self, event: &Event) -> HandleEventResult {
        let Event::Key(key_event) = event else {
            return HandleEventResult::Ignored;
        };
        match key_event.code {
            KeyCode::Up => self.previous(),
            KeyCode::Down => self.next(),
            KeyCode::Enter => self.select(),
            KeyCode::Backspace => self.unselect(),
            _ => return HandleEventResult::Ignored,
        }
        HandleEventResult::Consumed
    }
}

type ConnectionDirection = InterfaceDirection;

impl ConnectionDirection {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Downstream => "Downstream",
            Self::Upstream => "Upstream",
        }
    }

    fn as_span(&self) -> Span {
        match self {
            Self::Downstream => Span::from("Downstream").light_red(),
            Self::Upstream => Span::from("Upstream").light_green(),
        }
    }
}

struct CapturedConnection {
    direction: ConnectionDirection,
    interface: Interface,
    description: String,
    packets: Vec<CapturedPacket>,
}

struct CapturedPacket {
    direction: PacketDirection,
    data: Bytes,
    packet_type: Option<PacketType>,
    packet_len: Option<u16>,
    short_string: Option<String>,
    details_formatter: PacketFormatter,
}

impl CapturedPacket {
    fn try_parse(&mut self, connection_direction: ConnectionDirection) {
        if self.data.is_empty() {
            self.packet_type = Some(PacketType::None);
            self.packet_len = Some(0);
            self.short_string = Some("Missing header".to_owned());
            self.details_formatter = PacketFormatter::string("Missing header");
            return;
        }

        if self.data.len() == 2 && self.data[0..2] == [0x00, 0x04] {
            self.packet_type = Some(PacketType::SPIRCMagic);
            self.packet_len = Some(2);
            self.short_string = Some("SPIRC Magic - 0x00 0x04".to_owned());
            self.details_formatter = PacketFormatter::string("SPIRC Magic - 0x00 0x04");
            return;
        }

        // Check if its unencrypted, they use a 4 byte header
        if self.data.len() > 4 {
            let len = u32::from_be_bytes(self.data[0..4].try_into().unwrap()) as usize;
            if len == self.data.len() + 2 {
                if let Ok(client_hello) = keyexchange_old::ClientHello::parse_from_bytes(&self.data[4..]) {
                    self.packet_type = Some(PacketType::ClientHello);
                    self.packet_len = Some(self.data.len() as u16);
                    let product = if client_hello.build_info.has_product() {
                        Some(client_hello.build_info.product())
                    } else {
                        None
                    };
                    let platform = if client_hello.build_info.has_platform() {
                        Some(client_hello.build_info.platform())
                    } else {
                        None
                    };
                    let version = if client_hello.build_info.has_version() {
                        Some(client_hello.build_info.version())
                    } else {
                        None
                    };
                    self.short_string =
                        Some(format!("Product: {product:?} Platform: {platform:?} Version: {version:?}"));
                    self.details_formatter = PacketFormatter::ClientHello(client_hello);
                    return;
                }
            } else if len == self.data.len() {
                match (connection_direction, &self.direction) {
                    (ConnectionDirection::Upstream, PacketDirection::Recv) |
                    (ConnectionDirection::Downstream, PacketDirection::Send) => {
                        if let Ok(ap_response) = keyexchange_old::APResponseMessage::parse_from_bytes(&self.data[4..]) {
                            self.packet_type = Some(PacketType::APChallenge);
                            self.packet_len = Some(len as u16);
                            self.short_string = None;
                            self.details_formatter = PacketFormatter::APResponseMessage(ap_response);
                            return;
                        }
                    },
                    (ConnectionDirection::Upstream, PacketDirection::Send) |
                    (ConnectionDirection::Downstream, PacketDirection::Recv) => {
                        if let Ok(client_response) =
                            keyexchange_old::ClientResponsePlaintext::parse_from_bytes(&self.data[4..])
                        {
                            self.packet_type = Some(PacketType::ClientResponsePlaintext);
                            self.packet_len = Some(len as u16);
                            self.short_string = None;
                            self.details_formatter = PacketFormatter::ClientResponsePlaintext(client_response);
                            return;
                        }
                    },
                }
            }
        }

        let packet_type = PacketType::from_primitive(self.data[0]);
        self.packet_type = Some(packet_type.clone());

        if self.data.len() < 3 {
            self.packet_len = Some(0);
            self.short_string = Some("Invalid packet header - Missing length".to_owned());
            self.details_formatter = PacketFormatter::string("Invalid packet header - Missing length");
            return;
        }
        let packet_len = u16::from_be_bytes([self.data[1], self.data[2]]);
        self.packet_len = Some(packet_len);

        if packet_len == 0 {
            self.short_string = Some("Empty packet".to_owned());
            self.details_formatter = PacketFormatter::string("Empty packet");
            return;
        }

        if self.try_parse_packet(packet_type, self.data.slice(3..)).is_err() {
            let hex = hex::encode(&self.data[3..]);
            self.short_string = Some(hex.clone());
            self.details_formatter = PacketFormatter::Hex(self.data.clone());
        }
    }

    fn try_parse_packet(&mut self, packet_type: PacketType, mut buffer: Bytes) -> anyhow::Result<()> {
        match packet_type {
            PacketType::Ping => {
                let unix_offset = Duration::from_secs(buffer.try_get_u32()? as _);
                let timestamp = OffsetDateTime::UNIX_EPOCH + unix_offset;
                let formatted_timestamp = timestamp.format(&Rfc3339).unwrap_or(unix_offset.as_secs().to_string());
                let display = format!("Ping at {formatted_timestamp}");
                self.short_string = Some(display.clone());
                self.details_formatter = PacketFormatter::String(display);
                Ok(())
            },
            PacketType::ProductInfo => {
                use xml::{
                    reader::ParserConfig,
                    writer::{EmitterConfig, XmlEvent},
                };

                let mut element_counter = 0;
                let reader = ParserConfig::new().trim_whitespace(true).create_reader(buffer.deref());
                let mut dest = Vec::new();
                let mut writer = EmitterConfig::new().perform_indent(true).create_writer(&mut dest);
                for event in reader {
                    if let Some(event) = event?.as_writer_event() {
                        if let XmlEvent::StartElement { name, .. } = &event {
                            if name.local_name != "products" && name.local_name != "product" {
                                element_counter += 1;
                            }
                        }
                        writer.write(event)?;
                    }
                }
                let formatted_xml = String::from_utf8(dest)?;

                self.short_string = Some(format!("A/B config with {element_counter} elements"));
                self.details_formatter = PacketFormatter::String(formatted_xml);
                Ok(())
            },
            PacketType::CountryCode => {
                let code = String::from_utf8(buffer.to_vec())?;
                let display = format!("Country Code: {code}");
                self.short_string = Some(display.clone());
                self.details_formatter = PacketFormatter::String(display);
                Ok(())
            },
            PacketType::LegacyWelcome => {
                let display = "Welcome! (empty packet)".to_owned();
                self.short_string = Some(display.clone());
                self.details_formatter = PacketFormatter::String(display);
                Ok(())
            },
            PacketType::MercuryReq => {
                let packet = MercuryPacket::try_from_bytes(buffer)?;
                if let Ok(request) = MercuryPacketWithHeader::try_from_packet(&packet) {
                    self.short_string = Some(request.short_description());
                    self.details_formatter = PacketFormatter::MercuryPacketWithHeader(request);
                } else {
                    self.short_string = Some(packet.short_description());
                    self.details_formatter = PacketFormatter::MercuryPacket(packet);
                }
                Ok(())
            },
            PacketType::MercurySub => {
                let packet = MercuryPacket::try_from_bytes(buffer)?;
                self.short_string = Some(packet.short_description());
                self.details_formatter = PacketFormatter::MercuryPacket(packet);
                Ok(())
            },
            PacketType::MercuryUnsub => {
                let packet = MercuryPacket::try_from_bytes(buffer)?;
                self.short_string = Some(packet.short_description());
                self.details_formatter = PacketFormatter::MercuryPacket(packet);
                Ok(())
            },
            PacketType::MercuryEvent => {
                let packet = MercuryPacket::try_from_bytes(buffer)?;
                if let Ok(request) = MercuryPacketWithHeader::try_from_packet(&packet) {
                    self.short_string = Some(request.short_description());
                    self.details_formatter = PacketFormatter::MercuryPacketWithHeader(request);
                } else {
                    self.short_string = Some(packet.short_description());
                    self.details_formatter = PacketFormatter::MercuryPacket(packet);
                }
                Ok(())
            },
            _ => Err(anyhow!("Unhandled packet type")),
        }
    }
}

impl PacketDirection {
    fn as_span(&self) -> Span {
        match self {
            Self::Recv => Span::from("Recv").light_red(),
            Self::Send => Span::from("Send").light_green(),
        }
    }
}

#[derive(Debug, Clone, FromPrimitive)]
#[repr(u8)]
enum PacketType {
    None = 0x00,
    SecretBlock = 0x02,
    Ping = 0x04,
    StreamChunk = 0x08,
    StreamChunkRes = 0x09,
    ChannelError = 0x0a,
    ChannelAbort = 0x0b,
    RequestKey = 0x0c,
    AesKey = 0x0d,
    AesKeyError = 0x0e,
    Image = 0x19,
    CountryCode = 0x1b,
    Pong = 0x49,
    PongAck = 0x4a,
    Pause = 0x4b,
    ProductInfo = 0x50,
    LegacyWelcome = 0x69,
    LicenseVersion = 0x76,
    Login = 0xab,
    APWelcome = 0xac,
    AuthFailure = 0xad,
    MercuryReq = 0xb2,
    MercurySub = 0xb3,
    MercuryUnsub = 0xb4,
    MercuryEvent = 0xb5,
    TrackEndedTime = 0x82,
    PreferredLocale = 0x74,

    // These aren't real, used for displaying
    SPIRCMagic = 0xf0,
    ClientHello = 0xf1,
    APChallenge = 0xf2,
    ClientResponsePlaintext = 0xf3,

    #[num_enum(catch_all)]
    Unknown(u8),
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::SecretBlock => write!(f, "SecretBlock"),
            Self::Ping => write!(f, "Ping"),
            Self::StreamChunk => write!(f, "StreamChunk"),
            Self::StreamChunkRes => write!(f, "StreamChunkResponse"),
            Self::ChannelError => write!(f, "ChannelError"),
            Self::ChannelAbort => write!(f, "ChannelAbort"),
            Self::RequestKey => write!(f, "RequestKey"),
            Self::AesKey => write!(f, "AesKey"),
            Self::AesKeyError => write!(f, "AesKeyError"),
            Self::Image => write!(f, "Image"),
            Self::CountryCode => write!(f, "CountryCode"),
            Self::Pong => write!(f, "Pong"),
            Self::PongAck => write!(f, "PongAck"),
            Self::Pause => write!(f, "Pause"),
            Self::ProductInfo => write!(f, "ProductInfo"),
            Self::LegacyWelcome => write!(f, "LegacyWelcome"),
            Self::LicenseVersion => write!(f, "LicenseVersion"),
            Self::Login => write!(f, "Login"),
            Self::APWelcome => write!(f, "APWelcome"),
            Self::AuthFailure => write!(f, "AuthFailure"),
            Self::MercuryReq => write!(f, "MercuryReq"),
            Self::MercurySub => write!(f, "MercurySub"),
            Self::MercuryUnsub => write!(f, "MercuryUnsub"),
            Self::MercuryEvent => write!(f, "MercuryEvent"),
            Self::TrackEndedTime => write!(f, "TrackEndedTime"),
            Self::PreferredLocale => write!(f, "PreferredLocale"),
            Self::SPIRCMagic => write!(f, "SPIRC Magic"),
            Self::ClientHello => write!(f, "ClientHello"),
            Self::APChallenge => write!(f, "APChallenge"),
            Self::ClientResponsePlaintext => write!(f, "ClientResponsePlaintext"),
            Self::Unknown(value) => write!(f, "Unknown({value:#04x})"),
        }
    }
}

enum PacketFormatter {
    String(String),
    Hex(Bytes),
    ClientHello(keyexchange_old::ClientHello),
    APResponseMessage(keyexchange_old::APResponseMessage),
    ClientResponsePlaintext(keyexchange_old::ClientResponsePlaintext),
    MercuryPacket(MercuryPacket),
    MercuryPacketWithHeader(MercuryPacketWithHeader),
}

impl PacketFormatter {
    fn string<S: AsRef<str>>(str: S) -> Self {
        Self::String(str.as_ref().to_string())
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        fn render_doc<'a>(doc: DocBuilder<'a, pretty::Arena<'a>>, width: usize) -> String {
            let mut buffer = Vec::new();
            if let Err(render_error) = doc.1.render(width, &mut buffer) {
                format!("Failed to render: {render_error:?}")
            } else {
                match String::from_utf8(buffer) {
                    Ok(text) => text,
                    Err(utf8_error) => format!("Failed to decode rendered text: {utf8_error}"),
                }
            }
        }

        let paragraph = match self {
            Self::String(str) => Paragraph::new(str.as_str()),
            Self::Hex(bytes) => {
                let width = area.width as usize / 2;
                let lines = bytes.par_chunks(width).map(hex::encode).map(Line::from).collect::<Vec<_>>();
                Paragraph::new(lines)
            },
            Self::ClientHello(client_hello) => {
                let arena = pretty::Arena::<()>::new();
                let doc = keyexchange::format_client_hello(client_hello, &arena);
                Paragraph::new(render_doc(doc, area.width as usize))
            },
            Self::MercuryPacket(mercury_packet) => {
                let arena = pretty::Arena::<()>::new();
                let doc = mercury::format_mercury_packet(mercury_packet, &arena);
                Paragraph::new(render_doc(doc, area.width as usize))
            },
            Self::MercuryPacketWithHeader(mercury_packet) => {
                let arena = pretty::Arena::<()>::new();
                let doc = mercury::format_mercury_packet_with_header(mercury_packet, &arena);
                Paragraph::new(render_doc(doc, area.width as usize))
            },
            _ => Paragraph::new("Unsupported"),
        };
        let block = Block::new().borders(Borders::TOP);
        frame.render_widget(paragraph.block(block), area);
    }
}

#[derive(Clone)]
struct MercuryPacket {
    seq_len: u16,
    seq: u64,
    flags: u8,
    parts: Box<[(u16, Bytes)]>,
}

impl MercuryPacket {
    fn try_from_bytes(mut buffer: Bytes) -> anyhow::Result<Self> {
        let seq_len = buffer.try_get_u16()?;
        let seq = match seq_len {
            2 => buffer.try_get_u16()? as u64,
            4 => buffer.try_get_u32()? as u64,
            8 => buffer.try_get_u64()?,
            _ => return Err(anyhow!("Invalid sequence length {seq_len}")),
        };
        let flags = buffer.try_get_u8()?;
        let part_count = buffer.try_get_u16()?;
        let mut parts = Vec::with_capacity(part_count as usize);
        for _ in 0..part_count {
            let part_len = buffer.try_get_u16()?;
            let part = buffer.slice(0..(part_len as usize));
            buffer.advance(part_len as usize);
            parts.push((part_len, part));
        }
        let parts = parts.into_boxed_slice();
        Ok(Self { seq_len, seq, flags, parts })
    }

    fn short_description(&self) -> String {
        format!(
            "SeqLen: {}  Seq: {:#018x}  Flags: {}  Parts: {}",
            self.seq_len,
            self.seq,
            if self.flags == 1 {
                "M_FINAL"
            } else {
                "M_NONE"
            },
            self.parts.len()
        )
    }
}

struct MercuryPacketWithHeader {
    packet: MercuryPacket,
    header: mercury_old::Header,
    parts: Box<[(u16, Bytes)]>,
}

impl MercuryPacketWithHeader {
    fn try_from_packet(packet: &MercuryPacket) -> anyhow::Result<Self> {
        if packet.parts.is_empty() {
            return Err(anyhow!("Missing header in mercury request"));
        }
        let (_, header_buffer) = &packet.parts[0];
        let header = mercury_old::Header::parse_from_bytes(header_buffer)?;
        let parts = packet.parts.iter().skip(1).cloned().collect::<Box<[_]>>();
        Ok(Self { packet: packet.clone(), header, parts })
    }

    fn short_description(&self) -> String {
        format!(
            "Seq: {:#018x}  Method: {}  URI: {}  Parts: {}",
            self.packet.seq,
            if self.header.has_method() {
                self.header.method()
            } else {
                "<none>"
            },
            if self.header.has_uri() {
                self.header.uri()
            } else {
                "<none>"
            },
            self.parts.len(),
        )
    }
}

fn pb_enum_str<E: protobuf::Enum + std::fmt::Debug>(e: &protobuf::EnumOrUnknown<E>) -> String {
    e.enum_value().map(|f| format!("{f:?}")).unwrap_or(e.value().to_string())
}

fn pb_bytes_str(bytes: &[u8]) -> String {
    use base64::Engine;

    if let Ok(str) = str::from_utf8(bytes) {
        let str = str.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r");
        format!("(bytes-as-str) {str}")
    } else {
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        format!("(bytes) {b64}")
    }
}

const INDENT_SIZE: usize = 2;

mod keyexchange {
    use pretty::{DocAllocator, DocBuilder};

    use super::{pb_bytes_str, pb_enum_str, INDENT_SIZE};
    use crate::proto::keyexchange_old::{
        BuildInfo, ClientHello, FeatureSet, LoginCryptoDiffieHellmanHello, LoginCryptoHelloUnion, StreamingRules, Trial,
    };

    pub fn format_client_hello<'a>(
        client_hello: &'a ClientHello, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if let Some(build_info) = client_hello.build_info.as_ref() {
            doc = doc
                .append(arena.text("build_info {"))
                .append(arena.hardline())
                .append(format_build_info(build_info, arena).indent(INDENT_SIZE))
                .append(arena.text("}"))
                .append(arena.hardline());
        }

        for fingerprint in &client_hello.fingerprints_supported {
            doc = doc
                .append(arena.text("fingerprints_supported:"))
                .append(arena.space())
                .append(pb_enum_str(fingerprint))
                .append(arena.hardline());
        }

        for cryptosuite in &client_hello.cryptosuites_supported {
            doc = doc
                .append(arena.text("cryptosuites_supported:"))
                .append(arena.space())
                .append(pb_enum_str(cryptosuite))
                .append(arena.hardline());
        }

        for powscheme in &client_hello.powschemes_supported {
            doc = doc
                .append(arena.text("powschemes_supported:"))
                .append(arena.space())
                .append(pb_enum_str(powscheme))
                .append(arena.hardline());
        }

        if let Some(login_crypto_hello) = client_hello.login_crypto_hello.as_ref() {
            doc = doc
                .append(arena.text("login_crypto_hello {"))
                .append(arena.hardline())
                .append(format_login_crypto_hello(login_crypto_hello, arena).indent(INDENT_SIZE))
                .append(arena.text("}"))
                .append(arena.hardline());
        }

        if client_hello.has_client_nonce() {
            doc = doc
                .append(arena.text("client_nonce:"))
                .append(arena.space())
                .append(arena.text(pb_bytes_str(client_hello.client_nonce())))
                .append(arena.hardline());
        }

        if client_hello.has_padding() {
            doc = doc
                .append(arena.text("padding:"))
                .append(arena.space())
                .append(arena.text(pb_bytes_str(client_hello.padding())))
                .append(arena.hardline());
        }

        if let Some(feature_set) = client_hello.feature_set.as_ref() {
            doc = doc
                .append(arena.text("feature_set {"))
                .append(arena.hardline())
                .append(format_feature_set(feature_set, arena).indent(INDENT_SIZE))
                .append(arena.text("}"))
                .append(arena.hardline());
        }

        doc
    }

    fn format_build_info<'a>(
        build_info: &'a BuildInfo, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if build_info.has_product() {
            doc = doc.append(arena.text(format!("product: {:?}", build_info.product()))).append(arena.hardline());
        }

        for product_flag in &build_info.product_flags {
            let flag =
                product_flag.enum_value().map(|flag| format!("{flag:?}")).unwrap_or(product_flag.value().to_string());
            doc = doc.append(arena.text("product_flag: ")).append(flag).append(arena.hardline());
        }

        if build_info.has_platform() {
            doc = doc.append(arena.text(format!("platform: {:?}", build_info.platform()))).append(arena.hardline());
        }

        if build_info.has_version() {
            doc = doc.append(arena.text(format!("version: {}", build_info.version()))).append(arena.hardline());
        }

        doc
    }

    fn format_login_crypto_hello<'a>(
        login_crypto_hello: &'a LoginCryptoHelloUnion, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if let Some(diffie_hellman) = login_crypto_hello.diffie_hellman.as_ref() {
            doc = doc
                .append(arena.text("diffie_hellman {"))
                .append(arena.hardline())
                .append(format_login_crypto_diffie_hellman_hello(diffie_hellman, arena).indent(INDENT_SIZE))
                .append(arena.text("}"))
                .append(arena.hardline())
        }

        doc
    }

    fn format_login_crypto_diffie_hellman_hello<'a>(
        diffie_hellman: &'a LoginCryptoDiffieHellmanHello, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if diffie_hellman.has_gc() {
            doc = doc
                .append(arena.text("gc:"))
                .append(arena.space())
                .append(arena.text(pb_bytes_str(diffie_hellman.gc())))
                .append(arena.hardline());
        }

        if diffie_hellman.has_server_keys_known() {
            // TODO: This is a bit field, only one key is ever used though
            doc = doc
                .append(arena.text("server_keys_known:"))
                .append(arena.space())
                .append(arena.text(diffie_hellman.server_keys_known().to_string()))
                .append(arena.hardline());
        }

        doc
    }

    fn format_feature_set<'a>(
        feature_set: &'a FeatureSet, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if feature_set.has_autoupdate2() {
            doc = doc
                .append("autoupdate2:")
                .append(arena.space())
                .append(feature_set.autoupdate2().to_string())
                .append(arena.hardline());
        }

        if feature_set.has_current_location() {
            doc = doc
                .append("current_location:")
                .append(arena.space())
                .append(feature_set.current_location().to_string())
                .append(arena.hardline());
        }

        if let Some(streaming_rules) = feature_set.supported_streaming_rules.as_ref() {
            doc = doc
                .append("supported_streaming_rules {")
                .append(arena.hardline())
                .append(format_streaming_rules(streaming_rules, arena).indent(INDENT_SIZE))
                .append(arena.text("}"))
                .append(arena.hardline());
        }

        if feature_set.has_unk_4() {
            doc = doc
                .append(arena.text("unk_4:"))
                .append(arena.space())
                .append(feature_set.unk_4().to_string())
                .append(arena.hardline());
        }

        if let Some(trial) = feature_set.trial.as_ref() {
            doc = doc
                .append("trial {")
                .append(arena.hardline())
                .append(format_trial(trial, arena).indent(INDENT_SIZE))
                .append(arena.text("}"))
                .append(arena.hardline());
        }

        doc
    }

    fn format_streaming_rules<'a>(
        streaming_rules: &'a StreamingRules, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if streaming_rules.has_dmca_radio() {
            doc = doc
                .append(arena.text("dmca_radio:"))
                .append(arena.space())
                .append(streaming_rules.dmca_radio().to_string())
                .append(arena.hardline());
        }

        if streaming_rules.has_unk_2() {
            doc = doc
                .append(arena.text("unk_2:"))
                .append(arena.space())
                .append(streaming_rules.unk_2().to_string())
                .append(arena.hardline());
        }

        if streaming_rules.has_shuffle_mode() {
            doc = doc
                .append(arena.text("shuffle_mode:"))
                .append(arena.space())
                .append(streaming_rules.shuffle_mode().to_string())
                .append(arena.hardline());
        }

        if streaming_rules.has_unk_4() {
            doc = doc
                .append(arena.text("unk_4:"))
                .append(arena.space())
                .append(streaming_rules.unk_4().to_string())
                .append(arena.hardline());
        }

        doc
    }

    fn format_trial<'a>(trial: &'a Trial, arena: &'a pretty::Arena<'a>) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if trial.has_no_autostart() {
            doc = doc
                .append(arena.text("no_autostart:"))
                .append(arena.space())
                .append(trial.no_autostart().to_string())
                .append(arena.hardline());
        }

        doc
    }
}

mod mercury {
    use bytes::Bytes;
    use pretty::{DocAllocator, DocBuilder};

    use super::{pb_bytes_str, MercuryPacket, MercuryPacketWithHeader, INDENT_SIZE};
    use crate::proto::mercury_old::Header;

    fn format_mercury_packet_fields<'a>(
        mercury_packet: &'a MercuryPacket, mut doc: DocBuilder<'a, pretty::Arena<'a>>, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        doc = doc
            .append(arena.text("seq_len:"))
            .append(arena.space())
            .append(mercury_packet.seq_len.to_string())
            .append(arena.hardline());
        doc = doc
            .append(arena.text("sequence:"))
            .append(arena.space())
            .append(format!("{:#018x}", mercury_packet.seq))
            .append(arena.hardline());
        doc = doc
            .append(arena.text("flags:"))
            .append(arena.space())
            .append(if mercury_packet.flags == 1 {
                "M_FINAL"
            } else {
                "M_NONE"
            })
            .append(arena.hardline());
        doc = doc
            .append(arena.text("part_count:"))
            .append(arena.space())
            .append(mercury_packet.parts.len().to_string())
            .append(arena.hardline());
        doc
    }

    fn format_mercury_packet_parts<'a>(
        parts: &[(u16, Bytes)], mut doc: DocBuilder<'a, pretty::Arena<'a>>, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        for (part_len, part) in parts {
            doc = doc
                .append(arena.text("part {"))
                .append(arena.hardline())
                .append(
                    {
                        let mut doc = arena.nil();

                        doc = doc
                            .append(arena.text("part_len:"))
                            .append(arena.space())
                            .append(part_len.to_string())
                            .append(arena.hardline());

                        doc = doc
                            .append(arena.text("part:"))
                            .append(arena.space())
                            .append(pb_bytes_str(part))
                            .append(arena.hardline());

                        doc
                    }
                    .indent(INDENT_SIZE),
                )
                .append(arena.text("}"))
                .append(arena.hardline());
        }
        doc
    }

    pub fn format_mercury_packet<'a>(
        mercury_packet: &'a MercuryPacket, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();
        doc = format_mercury_packet_fields(mercury_packet, doc, arena);
        doc = format_mercury_packet_parts(&mercury_packet.parts, doc, arena);
        doc
    }

    pub fn format_mercury_packet_with_header<'a>(
        mercury_request: &'a MercuryPacketWithHeader, arena: &'a pretty::Arena<'a>,
    ) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();
        doc = format_mercury_packet_fields(&mercury_request.packet, doc, arena);

        doc = doc
            .append(arena.text("header {"))
            .append(arena.hardline())
            .append(format_header(&mercury_request.header, arena).indent(INDENT_SIZE))
            .append(arena.text("}"))
            .append(arena.hardline());

        doc = format_mercury_packet_parts(&mercury_request.parts, doc, arena);
        doc
    }

    fn format_header<'a>(header: &'a Header, arena: &'a pretty::Arena<'a>) -> DocBuilder<'a, pretty::Arena<'a>> {
        let mut doc = arena.nil();

        if header.has_uri() {
            doc = doc.append(arena.text("uri:")).append(arena.space()).append(header.uri()).append(arena.hardline());
        }

        if header.has_content_type() {
            doc = doc
                .append(arena.text("content_type:"))
                .append(arena.space())
                .append(header.content_type())
                .append(arena.hardline());
        }

        if header.has_method() {
            doc = doc
                .append(arena.text("method:"))
                .append(arena.space())
                .append(header.method())
                .append(arena.hardline());
        }

        if header.has_status_code() {
            doc = doc
                .append(arena.text("status_code:"))
                .append(arena.space())
                .append(header.status_code().to_string())
                .append(arena.hardline());
        }

        for user_field in &header.user_fields {
            doc = doc
                .append(arena.text("user_field {"))
                .append(arena.hardline())
                .append(
                    {
                        let mut doc = arena.nil();

                        if user_field.has_key() {
                            doc = doc
                                .append(arena.text("key:"))
                                .append(arena.space())
                                .append(user_field.key())
                                .append(arena.hardline());
                        }

                        if user_field.has_value() {
                            doc = doc
                                .append(arena.text("value:"))
                                .append(arena.space())
                                .append(pb_bytes_str(user_field.value()))
                                .append(arena.hardline());
                        }

                        doc
                    }
                    .indent(INDENT_SIZE),
                )
                .append(arena.text("}"))
                .append(arena.hardline());
        }

        doc
    }
}
