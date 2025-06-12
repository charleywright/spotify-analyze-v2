use std::{collections::HashMap, path::PathBuf};

use anyhow::{anyhow, Context};
use clap::ArgMatches;
use count_digits::CountDigits;
use crossterm::event::{self, Event, KeyCode};
use num_enum::FromPrimitive;
use pcap_file::{
    pcapng::{
        blocks::{enhanced_packet::EnhancedPacketOption, interface_description::InterfaceDescriptionOption},
        Block, PcapNgParser,
    },
    DataLink, PcapError,
};
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState},
    Frame,
};

use crate::pcap::{Interface, InterfaceDirection, PacketDirection};

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
                packet_type: None,
                packet_len: None,
                short_string: None,
                formatted_string: None,
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
            let connection = &mut self.connections[connection_index];
            let packet_count = connection.packets.len();
            let largest_packet_len = connection
                .packets
                .iter_mut()
                .map(|p| {
                    p.try_parse();
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
                        packet.try_parse();
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
            frame.render_stateful_widget(table, area, &mut self.packet_state);

            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None);
            frame.render_stateful_widget(
                scrollbar,
                area.inner(Margin { vertical: 1, horizontal: 1 }),
                &mut self.packet_scroll_state,
            );
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
    data: Vec<u8>,
    packet_type: Option<PacketType>,
    packet_len: Option<u16>,
    short_string: Option<String>,
    formatted_string: Option<String>,
}

impl CapturedPacket {
    fn try_parse(&mut self) {
        if self.data.is_empty() {
            self.packet_type = Some(PacketType::None);
            self.packet_len = Some(0);
            self.short_string = Some("Missing header".to_owned());
            self.formatted_string = Some("Missing header".to_owned());
            return;
        }

        if self.data.len() == 2 && self.data == [0x00, 0x04] {
            self.packet_type = Some(PacketType::SPIRCMagic);
            self.packet_len = Some(2);
            self.short_string = Some("SPIRC Magic - 0x00 0x04".to_owned());
            self.formatted_string = Some("SPIRC Magic - 0x00 0x04".to_owned());
            return;
        }

        // Check if its unencrypted, they use a 4 byte header
        if self.data.len() > 4 {
            let len = u32::from_be_bytes(self.data[0..4].try_into().unwrap()) as usize;
            if len == self.data.len() + 2 {
                self.packet_type = Some(PacketType::ClientHello);
                self.packet_len = Some(self.data.len() as u16);
                let hex = hex::encode(&self.data[4..]);
                self.short_string = Some(hex.clone());
                self.formatted_string = Some(hex);
                return;
            } else if len == self.data.len() {
                if matches!(self.direction, PacketDirection::Recv) {
                    self.packet_type = Some(PacketType::APChallenge);
                    self.packet_len = Some(len as u16);
                    let hex = hex::encode(&self.data[4..]);
                    self.short_string = Some(hex.clone());
                    self.formatted_string = Some(hex);
                } else {
                    self.packet_type = Some(PacketType::ClientResponsePlaintext);
                    self.packet_len = Some(len as u16);
                    let hex = hex::encode(&self.data[4..]);
                    self.short_string = Some(hex.clone());
                    self.formatted_string = Some(hex);
                }
                return;
            }
        }

        let packet_type = PacketType::from_primitive(self.data[0]);
        self.packet_type = Some(packet_type.clone());

        if self.data.len() < 3 {
            self.packet_len = Some(0);
            self.short_string = Some("Invalid packet header - Missing length".to_owned());
            self.formatted_string = Some("Invalid packet header - Missing length".to_owned());
            return;
        }
        let packet_len = u16::from_be_bytes([self.data[1], self.data[2]]);
        self.packet_len = Some(packet_len);

        if packet_len == 0 {
            self.short_string = Some("Empty packet".to_owned());
            self.formatted_string = Some("Empty packet".to_owned());
            return;
        }

        // TODO: Implement parsing for the rest of the packet types
        let hex = hex::encode(&self.data[3..]);
        self.short_string = Some(hex.clone());
        self.formatted_string = Some(hex);
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
