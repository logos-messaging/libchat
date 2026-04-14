//! Terminal UI using ratatui.

use std::io::{self, Stdout};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};

use crate::app::ChatApp;

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initialize the terminal.
pub fn init() -> io::Result<Tui> {
    execute!(io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    let backend = CrosstermBackend::new(io::stdout());
    Terminal::new(backend)
}

/// Restore the terminal to its original state.
pub fn restore() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Draw the UI.
pub fn draw(frame: &mut Frame, app: &ChatApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Messages
            Constraint::Length(3),  // Input
            Constraint::Length(3),  // Status
        ])
        .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_messages(frame, app, chunks[1]);
    draw_input(frame, app, chunks[2]);
    draw_status(frame, app, chunks[3]);
}

fn draw_header(frame: &mut Frame, app: &ChatApp, area: Rect) {
    let title = match app.current_session() {
        Some(session) => format!(" 💬 Chat: {} ↔ {} ", app.user_name, session.remote_user),
        None => format!(" 💬 {} (no active chat - use /connect or /chats) ", app.user_name),
    };

    let header = Paragraph::new(title)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));

    frame.render_widget(header, area);
}

fn draw_messages(frame: &mut Frame, app: &ChatApp, area: Rect) {
    let remote_name = app
        .current_session()
        .map(|s| s.remote_user.as_str())
        .unwrap_or("Them");

    let messages: Vec<ListItem> = app
        .messages()
        .iter()
        .map(|msg| {
            let (prefix, style) = if msg.from_self {
                ("You", Style::default().fg(Color::Green))
            } else {
                (remote_name, Style::default().fg(Color::Yellow))
            };

            let content = Line::from(vec![
                Span::styled(format!("{}: ", prefix), style.add_modifier(Modifier::BOLD)),
                Span::raw(&msg.content),
            ]);

            ListItem::new(content)
        })
        .collect();

    let title = match app.current_session() {
        Some(session) => format!(" Messages with {} ", session.remote_user),
        None => " Messages ".to_string(),
    };

    let messages_widget = List::new(messages)
        .block(Block::default().title(title).borders(Borders::ALL));

    frame.render_widget(messages_widget, area);
}

fn draw_input(frame: &mut Frame, app: &ChatApp, area: Rect) {
    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(Color::White))
        .block(Block::default().title(" Input (Enter to send) ").borders(Borders::ALL));

    frame.render_widget(input, area);

    // Show cursor
    frame.set_cursor_position((
        area.x + app.input.len() as u16 + 1,
        area.y + 1,
    ));
}

fn draw_status(frame: &mut Frame, app: &ChatApp, area: Rect) {
    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().title(" Status ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    frame.render_widget(status, area);
}

/// Handle keyboard events.
pub fn handle_events(app: &mut ChatApp) -> io::Result<bool> {
    // Poll for events with a short timeout to allow checking incoming messages
    if event::poll(std::time::Duration::from_millis(100))? {
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(true);
            }

            match key.code {
                KeyCode::Esc => return Ok(false),
                // Handle Ctrl+C
                KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    return Ok(false);
                }
                KeyCode::Enter => {
                    if !app.input.is_empty() {
                        let input = std::mem::take(&mut app.input);
                        
                        if input.starts_with('/') {
                            match app.handle_command(&input) {
                                Ok(Some(response)) => {
                                    app.status = response;
                                }
                                Ok(None) => {
                                    // Quit signal
                                    return Ok(false);
                                }
                                Err(e) => {
                                    app.status = format!("Error: {}", e);
                                }
                            }
                        } else if app.current_session().is_some() {
                            if let Err(e) = app.send_message(&input) {
                                app.status = format!("Send error: {}", e);
                            }
                        } else {
                            app.status = "No active chat. Use /connect first.".to_string();
                        }
                    }
                }
                KeyCode::Char(c) => {
                    app.input.push(c);
                }
                KeyCode::Backspace => {
                    app.input.pop();
                }
                _ => {}
            }
        }
    }

    Ok(true)
}
