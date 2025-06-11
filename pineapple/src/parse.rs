use std::{collections::HashMap, path::PathBuf};

use anyhow::{anyhow, Context};
use clap::ArgMatches;
use count_digits::CountDigits;
use crossterm::event::{self, Event, KeyCode};
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
                formatted_string: FormattedString::NotAttempted,
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
        })
    }

    fn previous(&mut self) {
        if self.active_connection_index.is_none() {
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
        } else {
            todo!()
        }
    }

    fn next(&mut self) {
        if self.active_connection_index.is_none() {
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
        } else {
            todo!()
        }
    }

    fn select(&mut self) {
        if self.active_connection_index.is_none() {
            if let Some(idx) = self.connection_state.selected() {
                self.active_connection_index = Some(idx);
            }
        } else {
            todo!()
        }
    }

    fn unselect(&mut self) {
        // TODO: Check if packet is selected
        if self.active_connection_index.is_some() {
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
        if self.active_connection_index.is_none() {
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
    formatted_string: FormattedString,
}

enum FormattedString {
    NotAttempted,
    Success(String),
    Failed(String),
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
