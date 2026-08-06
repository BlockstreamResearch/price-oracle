use std::{
    collections::VecDeque,
    io::{self, Stdout},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use storm::{Peer, PeerStatus};
use tokio::sync::mpsc;

static LOG_SENDER: OnceLock<mpsc::UnboundedSender<String>> = OnceLock::new();
static LOGGER: TuiLogger = TuiLogger;

struct TuiLogger;

impl log::Log for TuiLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(sender) = LOG_SENDER.get() {
            let _ = sender.send(format!(
                "{timestamp} {:<5} {}",
                record.level(),
                record.args()
            ));
        }
    }

    fn flush(&self) {}
}

pub struct App {
    pub input: String,
    pub peers: Vec<Peer>,
    pub ready: bool,
    logs: VecDeque<String>,
    log_receiver: mpsc::UnboundedReceiver<String>,
}

impl App {
    pub fn new() -> io::Result<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let _ = LOG_SENDER.set(sender);
        log::set_logger(&LOGGER).map_err(|_| io::Error::other("logger is already installed"))?;
        log::set_max_level(log::LevelFilter::Info);
        Ok(Self {
            input: String::new(),
            peers: Vec::new(),
            ready: false,
            logs: VecDeque::new(),
            log_receiver: receiver,
        })
    }

    pub fn drain_logs(&mut self) {
        while let Ok(message) = self.log_receiver.try_recv() {
            self.logs.push_back(message);
            while self.logs.len() > 200 {
                self.logs.pop_front();
            }
        }
    }

    pub fn draw(&self, frame: &mut Frame<'_>) {
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(7),
                Constraint::Length(9),
                Constraint::Length(3),
            ])
            .split(frame.area());

        let ready = if self.ready { "READY" } else { "DISCOVERING" };
        let ready_color = if self.ready {
            Color::Green
        } else {
            Color::Yellow
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " STORM NODE  ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    ready,
                    Style::default()
                        .fg(ready_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {} peers", self.peers.len())),
            ]))
            .block(Block::default().borders(Borders::ALL)),
            areas[0],
        );

        let rows = self.peers.iter().map(|peer| {
            Row::new(vec![
                Cell::from(hex::encode(peer.compressed_public_key)),
                Cell::from(peer.socket_address.as_deref().unwrap_or("-")),
                Cell::from(status_name(peer.status)),
                Cell::from(if peer.discovery { "yes" } else { "no" }),
            ])
        });
        let header = Row::new(["Public key", "Address", "Status", "Discovery"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        frame.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(20),
                    Constraint::Percentage(45),
                    Constraint::Length(12),
                    Constraint::Length(10),
                ],
            )
            .header(header)
            .block(Block::default().title(" Peers ").borders(Borders::ALL)),
            areas[1],
        );

        let visible_log_lines = areas[2].height.saturating_sub(2) as usize;
        let visible_log_width = areas[2].width.saturating_sub(2) as usize;
        let wrapped_logs = self
            .logs
            .iter()
            .flat_map(|line| wrap(line, visible_log_width))
            .collect::<Vec<_>>();
        let first_visible_log = wrapped_logs.len().saturating_sub(visible_log_lines);
        let logs = wrapped_logs[first_visible_log..].join("\n");
        frame.render_widget(
            Paragraph::new(logs).block(Block::default().title(" Logs ").borders(Borders::ALL)),
            areas[2],
        );
        let input_style = if self.ready {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let visible_input_width = areas[3].width.saturating_sub(2) as usize;
        let visible_input = self
            .input
            .chars()
            .rev()
            .take(visible_input_width)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        frame.render_widget(
            Paragraph::new(visible_input.as_str())
                .style(input_style)
                .block(Block::default().title(" Broadcast ").borders(Borders::ALL)),
            areas[3],
        );
        if self.ready {
            frame.set_cursor_position((
                areas[3].x + visible_input.chars().count() as u16 + 1,
                areas[3].y + 1,
            ));
        }
    }
}

pub struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self { terminal })
    }

    pub fn draw(&mut self, app: &App) -> io::Result<()> {
        self.terminal.draw(|frame| app.draw(frame))?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn status_name(status: PeerStatus) -> &'static str {
    match status {
        PeerStatus::Controlled => "controlled",
        PeerStatus::Active => "active",
        PeerStatus::Inactive => "inactive",
        PeerStatus::Banned => "banned",
    }
}

fn wrap(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }

    let characters = value.chars().collect::<Vec<_>>();
    if characters.is_empty() {
        return vec![String::new()];
    }

    characters
        .chunks(width)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_wrap_to_the_available_width() {
        assert_eq!(wrap("123456789", 4), ["1234", "5678", "9"]);
    }
}
