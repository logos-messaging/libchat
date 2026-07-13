//! ratatui rendering: a grid of per-subscription panes, or one unified stream.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

/// The most recent messages retained per pane / in the unified stream.
const PANE_HISTORY: usize = 500;
const UNIFIED_HISTORY: usize = 1000;

/// One received message, as observed on the node callback thread.
#[derive(Clone)]
pub struct ObservedMessage {
    /// When the node delivered it; rendered as a delta from [`App::start`].
    pub received_at: Instant,
    pub content_topic: String,
    pub payload_len: usize,
    /// Hash of the payload bytes; identifies duplicate deliveries.
    pub message_id: u64,
}

/// A single subscription and the traffic observed on it.
pub struct Pane {
    /// Delivery address the user subscribed to (the pane title).
    pub address: String,
    /// Content topic derived from the address; used to route messages here.
    pub content_topic: String,
    /// A firehose pane: records every message regardless of content topic.
    pub match_all: bool,
    pub count: usize,
    pub total_bytes: usize,
    recent: VecDeque<ObservedMessage>,
}

impl Pane {
    pub fn new(address: String, content_topic: String) -> Self {
        Self {
            address,
            content_topic,
            match_all: false,
            count: 0,
            total_bytes: 0,
            recent: VecDeque::with_capacity(PANE_HISTORY),
        }
    }

    /// A firehose pane that records traffic on every content topic.
    pub fn catch_all() -> Self {
        Self {
            address: "ALL".into(),
            content_topic: String::new(),
            match_all: true,
            count: 0,
            total_bytes: 0,
            recent: VecDeque::with_capacity(PANE_HISTORY),
        }
    }

    /// Whether a message on `topic` belongs in this pane.
    pub fn matches(&self, topic: &str) -> bool {
        self.match_all || self.content_topic == topic
    }

    fn record(&mut self, msg: ObservedMessage) {
        self.count += 1;
        self.total_bytes += msg.payload_len;
        if self.recent.len() == PANE_HISTORY {
            self.recent.pop_back();
        }
        self.recent.push_front(msg);
    }
}

/// Keyboard focus: either navigating, or typing a new subscription address.
pub enum InputMode {
    Normal,
    /// Holds the delivery address typed so far.
    Adding(String),
}

/// How received traffic is laid out.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    /// One bordered pane per subscription, in a grid.
    Grid,
    /// A single merged stream across all subscriptions.
    Unified,
}

/// Whole-screen application state.
pub struct App {
    pub panes: Vec<Pane>,
    pub port: u16,
    pub preset: String,
    pub mode: InputMode,
    pub view: ViewMode,
    /// Reference point for the per-message delta timestamps.
    pub start: Instant,
    /// Newest-first merged stream, for [`ViewMode::Unified`].
    unified: VecDeque<ObservedMessage>,
    /// Transient one-line message (e.g. the result of the last subscribe).
    pub status: String,
}

impl App {
    pub fn new(panes: Vec<Pane>, port: u16, preset: String) -> Self {
        Self {
            panes,
            port,
            preset,
            mode: InputMode::Normal,
            view: ViewMode::Grid,
            start: Instant::now(),
            unified: VecDeque::with_capacity(UNIFIED_HISTORY),
            status: String::new(),
        }
    }

    /// Route an observed message to every pane that watches it, and to the
    /// unified stream. A message on a named topic lands in both its pane and any
    /// firehose (`ALL`) pane.
    pub fn record(&mut self, msg: ObservedMessage) {
        for pane in self.panes.iter_mut().filter(|p| p.matches(&msg.content_topic)) {
            pane.record(msg.clone());
        }
        if self.unified.len() == UNIFIED_HISTORY {
            self.unified.pop_back();
        }
        self.unified.push_front(msg);
    }

    pub fn toggle_view(&mut self) {
        self.view = match self.view {
            ViewMode::Grid => ViewMode::Unified,
            ViewMode::Unified => ViewMode::Grid,
        };
    }

    /// Whether a pane already watches this content topic.
    pub fn has_topic(&self, content_topic: &str) -> bool {
        self.panes.iter().any(|p| p.content_topic == content_topic)
    }

    pub fn push_pane(&mut self, address: String, content_topic: String) {
        self.panes.push(Pane::new(address, content_topic));
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    match &app.mode {
        InputMode::Adding(buffer) => {
            let outer = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(3),
                    Constraint::Length(3),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(frame.area());
            draw_header(frame, app, outer[0]);
            draw_body(frame, app, outer[1]);
            draw_input(frame, buffer, outer[2]);
            draw_status(frame, app, outer[3]);
            draw_commands(frame, outer[4]);
        }
        InputMode::Normal => {
            let outer = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(3),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(frame.area());
            draw_header(frame, app, outer[0]);
            draw_body(frame, app, outer[1]);
            draw_status(frame, app, outer[2]);
            draw_commands(frame, outer[3]);
        }
    }
}

/// Top bar: the app name and the network (preset) the node is connected to.
fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let spans = vec![
        Span::styled(
            " meshshark ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  network "),
        Span::styled(
            app.preset.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  ·  port {}", app.port), Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_body(frame: &mut Frame, app: &App, area: Rect) {
    match app.view {
        ViewMode::Grid => draw_panes(frame, app, area),
        ViewMode::Unified => draw_unified(frame, app, area),
    }
}

fn draw_input(frame: &mut Frame, buffer: &str, area: Rect) {
    let input = Paragraph::new(format!("{buffer}▏")).block(
        Block::default()
            .title(" Add subscription (Enter to confirm, Esc to cancel) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(input, area);
}

fn draw_panes(frame: &mut Frame, app: &App, area: Rect) {
    if app.panes.is_empty() {
        let hint = Paragraph::new(
            "No subscriptions. Press 'a' to add a delivery address, or pass --sub at launch.",
        )
        .block(Block::default().title(" meshshark ").borders(Borders::ALL));
        frame.render_widget(hint, area);
        return;
    }

    // Arrange panes in a roughly square grid.
    let n = app.panes.len();
    let cols = (n as f64).sqrt().ceil() as usize;
    let rows = n.div_ceil(cols);

    let row_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Ratio(1, rows as u32); rows])
        .split(area);

    for (r, row_area) in row_areas.iter().enumerate() {
        let start = r * cols;
        let end = (start + cols).min(n);
        let in_row = end - start;
        if in_row == 0 {
            break;
        }
        let col_areas = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Ratio(1, cols as u32); cols])
            .split(*row_area);
        for (c, pane) in app.panes[start..end].iter().enumerate() {
            draw_pane(frame, pane, col_areas[c], app.start);
        }
    }
}

fn draw_pane(frame: &mut Frame, pane: &Pane, area: Rect, start: Instant) {
    // Firehose panes span every topic, so they keep their "ALL" label; a
    // single-topic pane is titled with its content topic.
    let label = if pane.match_all {
        pane.address.as_str()
    } else {
        pane.content_topic.as_str()
    };
    let title = format!(" {}  ({} msgs, {}) ", label, pane.count, human_bytes(pane.total_bytes),);
    // Color the border by topic so a pane's color matches its lines in the
    // unified view. A firehose pane mixes topics, so leave it neutral.
    let border_color = if pane.match_all {
        Color::Gray
    } else {
        topic_color(&pane.content_topic)
    };

    let items: Vec<ListItem> = pane
        .recent
        .iter()
        .map(|m| ListItem::new(message_line(m, start, pane.match_all)))
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(Span::styled(
                title,
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(list, area);
}

fn draw_unified(frame: &mut Frame, app: &App, area: Rect) {
    let title = format!(" unified  ({} msgs) ", app.unified.len());
    let items: Vec<ListItem> = app
        .unified
        .iter()
        .map(|m| ListItem::new(message_line(m, app.start, true)))
        .collect();
    let list = List::new(items).block(
        Block::default()
            .title(Span::styled(
                title,
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}

/// One line per message: delta from start, message id, optionally the
/// color-coded topic, then the payload size. `show_topic` is set for unified /
/// firehose views where lines mix topics; per-subscription panes carry the
/// color on the border.
fn message_line(m: &ObservedMessage, start: Instant, show_topic: bool) -> Line<'static> {
    let mut spans = vec![
        Span::styled(
            fmt_delta(m.received_at.saturating_duration_since(start)),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  "),
        Span::styled(short_id(m.message_id), Style::default().fg(Color::Magenta)),
        Span::raw("  "),
    ];
    if show_topic {
        spans.push(Span::styled(
            m.content_topic.clone(),
            Style::default().fg(topic_color(&m.content_topic)),
        ));
        spans.push(Span::raw("  "));
    }
    spans.push(Span::styled(
        format!("{:>9}", human_bytes(m.payload_len)),
        Style::default().fg(Color::Cyan),
    ));
    Line::from(spans)
}

/// The message id as a fixed-width 8-hex-digit tag, e.g. `#a1b2c3d4`.
fn short_id(id: u64) -> String {
    format!("#{:08x}", id as u32)
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let total: usize = app.panes.iter().map(|p| p.count).sum();
    let view = match app.view {
        ViewMode::Grid => "grid",
        ViewMode::Unified => "unified",
    };
    let text = if app.status.is_empty() {
        format!(" {} subs · {} msgs · view {} ", app.panes.len(), total, view)
    } else {
        format!(" {} ", app.status)
    };
    let status = Paragraph::new(text).style(Style::default().fg(Color::Black).bg(Color::Gray));
    frame.render_widget(status, area);
}

/// Persistent key-hint bar: each command's key in bold, its action dimmed.
fn draw_commands(frame: &mut Frame, area: Rect) {
    const COMMANDS: &[(&str, &str)] = &[
        ("a", "add sub"),
        ("v/Tab", "toggle view"),
        ("q/Esc", "quit"),
        ("^C", "quit"),
    ];
    let mut spans = vec![Span::raw(" ")];
    for (i, (key, action)) in COMMANDS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ·  ", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(
            *key,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(*action, Style::default().fg(Color::Gray)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Stable color per content topic, so a topic looks the same across frames and
/// between the grid border and the unified label. FNV-1a over the topic bytes.
fn topic_color(topic: &str) -> Color {
    const PALETTE: &[Color] = &[
        Color::Cyan,
        Color::Green,
        Color::Yellow,
        Color::Magenta,
        Color::Blue,
        Color::Red,
        Color::LightCyan,
        Color::LightGreen,
        Color::LightYellow,
        Color::LightMagenta,
        Color::LightBlue,
        Color::LightRed,
    ];
    let mut h: u32 = 2166136261;
    for b in topic.bytes() {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    PALETTE[(h as usize) % PALETTE.len()]
}

/// Elapsed time as a fixed-width `+MM:SS.ss`, so the column always aligns.
fn fmt_delta(d: Duration) -> String {
    let secs = d.as_secs_f64();
    let mins = (secs / 60.0) as u64;
    format!("+{:02}:{:05.2}", mins, secs - (mins * 60) as f64)
}

fn human_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}
