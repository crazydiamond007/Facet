//! What a reattaching client should be shown.
//!
//! Replaying the raw byte stream works fine for a shell printing lines, and it
//! breaks badly for `vim`, `htop` or `less`. Those programs use the *alternate
//! screen*: they switch to a second, scrollback-less buffer, paint it once, and
//! from then on send only the differences, with relative cursor moves.
//!
//! A ring buffer of recent bytes cannot survive that. Once the oldest bytes fall
//! off the front, the `ESC[?1049h` that entered the alternate screen and the
//! initial full paint are the first things to go, and what is left is a stream of
//! diffs against a screen the reattaching client never had. Replaying them into a
//! blank terminal produces exactly the mess you would expect. Worse, the ring is
//! trimmed at an arbitrary byte offset, so it can slice an escape sequence in
//! half and hand the client half a control code.
//!
//! So the server has to understand the bytes rather than hoard them. This module
//! keeps two things, mirroring what a real terminal keeps:
//!
//! * **History**: the bytes written to the *normal* screen, and only those. A
//!   real terminal does not put alternate-screen output into scrollback either:
//!   you cannot scroll back through vim after you quit it, and you should not be
//!   able to here.
//! * **A screen**: a live terminal emulator fed every byte, so the *current*
//!   screen can be reconstructed from scratch at any moment, however long ago it
//!   was painted and however much has since been evicted.
//!
//! On attach, the replay is the history, plus, if a full-screen program is
//! running right now, the escape codes to re-enter the alternate screen and
//! repaint it. Quitting vim then restores the history underneath, because that is
//! precisely what the client's own saved normal screen contains.

use std::collections::VecDeque;

use crate::pty::Size;

/// Longest escape sequence we will hold back before deciding it is malformed.
///
/// Real ones are far shorter. The cap exists so a stream of garbage that happens
/// to start with `ESC[` cannot make us buffer without bound.
const MAX_SEQUENCE: usize = 32;

/// Tracks whether the shell is on the alternate screen, byte by byte, and tells
/// the caller which bytes belong to the normal screen.
///
/// This is a state machine rather than a search over each chunk because a pty
/// hands you arbitrary slices: `ESC[?1049h` can and does arrive split across two
/// reads. A searcher would miss the halves and, worse, would already have written
/// the first half into the history, leaving a severed control code to be replayed
/// at some unsuspecting client later.
///
/// So bytes of an in-progress sequence are held back until it completes. Then it
/// is either an alternate-screen switch, which is swallowed, or it is anything
/// else, which is released intact.
#[derive(Default)]
struct AltScreen {
    state: State,
    /// The escape sequence being assembled, if any.
    pending: Vec<u8>,
    in_alt: bool,
}

#[derive(Default, PartialEq)]
enum State {
    #[default]
    Ground,
    /// Seen `ESC`.
    Escape,
    /// Seen `ESC[`; collecting parameters up to the final byte.
    Csi,
}

impl AltScreen {
    /// Feed a chunk. Every byte belonging to the *normal* screen is handed to
    /// `emit`, in order. Alternate-screen bytes, and the switches themselves,
    /// are dropped.
    fn feed(&mut self, chunk: &[u8], emit: &mut impl FnMut(u8)) {
        for &byte in chunk {
            match self.state {
                State::Ground => {
                    if byte == 0x1b {
                        self.state = State::Escape;
                        self.pending.clear();
                        self.pending.push(byte);
                    } else if !self.in_alt {
                        emit(byte);
                    }
                }

                State::Escape => {
                    self.pending.push(byte);
                    if byte == b'[' {
                        self.state = State::Csi;
                    } else {
                        // Not a CSI. Nothing we care about, so let it through.
                        self.release(emit);
                    }
                }

                State::Csi => {
                    self.pending.push(byte);

                    // Final byte of a CSI sequence.
                    if (0x40..=0x7e).contains(&byte) {
                        if is_alt_switch(&self.pending) {
                            // Swallow it: the client is told about the alternate
                            // screen by `replay`, reconstructed, not by replaying
                            // a switch whose paint may have been evicted.
                            self.in_alt = self.pending.ends_with(b"h");
                            self.pending.clear();
                            self.state = State::Ground;
                        } else {
                            self.release(emit);
                        }
                    } else if self.pending.len() > MAX_SEQUENCE {
                        // Malformed or something exotic. Do not hold it hostage.
                        self.release(emit);
                    }
                }
            }
        }
    }

    /// Hand the buffered sequence to the caller and go back to Ground.
    fn release(&mut self, emit: &mut impl FnMut(u8)) {
        if !self.in_alt {
            for &byte in &self.pending {
                emit(byte);
            }
        }
        self.pending.clear();
        self.state = State::Ground;
    }
}

/// Is this CSI sequence a switch to or from the alternate screen?
///
/// `1049` is the modern one (switch, save the cursor, clear). `1047` and `47`
/// are the older forms, still emitted by some programs, so all three count.
/// `1048` is cursor save/restore *only* and is deliberately not here: treating it
/// as a screen switch would swallow a sequence that changes no screen at all.
fn is_alt_switch(sequence: &[u8]) -> bool {
    let Some(body) = sequence.strip_prefix(b"\x1b[?") else {
        return false;
    };
    let Some((final_byte, params)) = body.split_last() else {
        return false;
    };
    if !matches!(final_byte, b'h' | b'l') {
        return false;
    }

    params
        .split(|&b| b == b';')
        .any(|param| matches!(param, b"47" | b"1047" | b"1049"))
}

/// The replayable state of one terminal.
pub struct Screen {
    /// Normal-screen bytes, oldest dropped first. This is the scrollback.
    history: VecDeque<u8>,
    history_cap: usize,
    alt: AltScreen,
    /// Fed every byte, so the current screen can always be redrawn from nothing.
    parser: vt100::Parser,
}

impl Screen {
    pub fn new(size: Size, history_cap: usize) -> Self {
        Self {
            history: VecDeque::new(),
            history_cap,
            alt: AltScreen::default(),
            // No scrollback in the emulator: `history` above is the scrollback,
            // and it holds raw bytes, which reproduce colour and wrapping exactly
            // as the shell wrote them. The emulator only ever has to answer "what
            // is on the screen right now".
            parser: vt100::Parser::new(size.rows, size.cols, 0),
        }
    }

    /// Absorb a chunk of pty output.
    pub fn ingest(&mut self, chunk: &[u8]) {
        self.parser.process(chunk);

        let history = &mut self.history;
        self.alt.feed(chunk, &mut |byte| history.push_back(byte));

        let overflow = self.history.len().saturating_sub(self.history_cap);
        if overflow > 0 {
            self.history.drain(..overflow);
        }
    }

    pub fn resize(&mut self, size: Size) {
        self.parser.screen_mut().set_size(size.rows, size.cols);
    }

    /// Everything a client attaching *now* must be sent to see what a client
    /// that never disconnected is seeing.
    pub fn replay(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.history.iter().copied().collect();

        let screen = self.parser.screen();
        if screen.alternate_screen() {
            // `state_formatted` reproduces the grid, the attributes and the
            // cursor, but it does *not* emit the switch itself, so we do. Without
            // this the client would paint vim onto its normal screen, and quitting
            // vim would restore whatever happened to be underneath instead of the
            // history we just replayed.
            out.extend_from_slice(b"\x1b[?1049h");
            out.extend_from_slice(&screen.state_formatted());
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: Size = Size { cols: 80, rows: 24 };

    /// The normal-screen bytes the tracker lets through.
    fn normal(chunks: &[&[u8]]) -> Vec<u8> {
        let mut alt = AltScreen::default();
        let mut out = Vec::new();
        for chunk in chunks {
            alt.feed(chunk, &mut |byte| out.push(byte));
        }
        out
    }

    #[test]
    fn ordinary_output_passes_straight_through() {
        assert_eq!(normal(&[b"hello\r\n"]), b"hello\r\n");
    }

    #[test]
    fn colour_sequences_survive_intact() {
        // The tracker holds escape sequences back while it decides what they are.
        // A colour code must come out the other side byte for byte, or every
        // replayed screen loses its colour.
        let coloured = b"\x1b[1;32mgreen\x1b[0m";
        assert_eq!(normal(&[coloured]), coloured);
    }

    #[test]
    fn alternate_screen_content_is_not_history() {
        // The heart of it. What vim draws must never reach the scrollback, for
        // the same reason a real terminal does not let you scroll back into it.
        let out = normal(&[b"before\x1b[?1049hVIM DRAWS HERE\x1b[?1049lafter"]);
        assert_eq!(out, b"beforeafter");
    }

    #[test]
    fn a_switch_split_across_two_reads_is_still_caught() {
        // The bug a chunk-by-chunk search would have shipped. A pty hands you
        // arbitrary slices, so the switch arrives in halves; miss it and the
        // first half is written into the history as a severed control code.
        let out = normal(&[b"before\x1b[?10", b"49hVIM\x1b[?1049l", b"after"]);
        assert_eq!(out, b"beforeafter");
    }

    #[test]
    fn the_older_alternate_screen_codes_count_too() {
        for code in [&b"47"[..], b"1047", b"1049"] {
            let mut input = Vec::from(b"a\x1b[?");
            input.extend_from_slice(code);
            input.extend_from_slice(b"hHIDDEN\x1b[?");
            input.extend_from_slice(code);
            input.extend_from_slice(b"lb");

            assert_eq!(
                normal(&[&input]),
                b"ab",
                "code {} was not treated as an alternate screen switch",
                String::from_utf8_lossy(code)
            );
        }
    }

    #[test]
    fn cursor_save_is_not_mistaken_for_a_screen_switch() {
        // 1048 saves the cursor and changes no screen. Swallowing it would eat a
        // sequence the client needs, and worse, would leave `in_alt` set.
        let input = b"a\x1b[?1048hb";
        assert_eq!(normal(&[input]), input);
    }

    #[test]
    fn a_runaway_sequence_is_released_rather_than_buffered_forever() {
        // Garbage that happens to start with ESC[ must not make us hold bytes
        // hostage indefinitely.
        let mut input = Vec::from(b"\x1b[");
        input.extend(std::iter::repeat_n(b'0', MAX_SEQUENCE * 2));

        let out = normal(&[&input]);
        assert!(
            out.len() >= MAX_SEQUENCE,
            "the tracker swallowed a malformed sequence instead of releasing it"
        );
    }

    #[test]
    fn history_is_capped_and_drops_the_oldest_first() {
        let mut screen = Screen::new(SIZE, 8);
        screen.ingest(b"0123456789");

        assert_eq!(screen.replay(), b"23456789");
    }

    #[test]
    fn a_normal_screen_replays_as_the_bytes_that_made_it() {
        let mut screen = Screen::new(SIZE, 1024);
        screen.ingest(b"$ echo hi\r\nhi\r\n$ ");

        assert_eq!(screen.replay(), b"$ echo hi\r\nhi\r\n$ ");
    }

    #[test]
    fn a_full_screen_program_is_reconstructed_not_replayed() {
        let mut screen = Screen::new(SIZE, 1024);

        screen.ingest(b"$ vim notes.txt\r\n");
        screen.ingest(b"\x1b[?1049h\x1b[H\x1b[2JHELLO FROM VIM");

        let replay = screen.replay();
        let text = String::from_utf8_lossy(&replay);

        // The history is there, and stops where vim began.
        assert!(text.starts_with("$ vim notes.txt\r\n"), "{text:?}");
        // The client is told to enter the alternate screen...
        assert!(text.contains("\x1b[?1049h"), "no alternate screen switch");
        // ...and vim's screen is painted from the emulator, not from the bytes.
        assert!(
            text.contains("HELLO FROM VIM"),
            "vim's screen was not redrawn"
        );
    }

    #[test]
    fn the_screen_survives_its_own_history_being_evicted() {
        // The actual bug. vim paints once and then sends only diffs. Evict the
        // paint, as a long session inevitably does, and a replay of the raw bytes
        // is a stream of diffs against a screen the client never had.
        //
        // Here the cap is tiny, so vim's paint is long gone from any byte log.
        // The screen must still come back, because it is rebuilt rather than
        // repeated.
        let mut screen = Screen::new(SIZE, 16);

        screen.ingest(b"$ vim notes.txt\r\n");
        screen.ingest(b"\x1b[?1049h\x1b[H\x1b[2JIMPORTANT WORK");

        // Now flood it with the kind of small diffs vim actually sends: a status
        // line at the bottom, rewritten on every keystroke. Each one is useless
        // on its own, which is the point. This is what a raw byte log degrades
        // into once the paint has been evicted.
        for line in 1..500 {
            screen.ingest(format!("\x1b[24;1Hline {line} of 500").as_bytes());
        }

        let replay = screen.replay();
        let text = String::from_utf8_lossy(&replay);

        assert!(
            text.contains("IMPORTANT WORK"),
            "the reattaching client would not have seen vim's screen at all"
        );
    }

    #[test]
    fn quitting_the_program_leaves_the_history_behind() {
        // After vim exits, the client's own saved normal screen is restored, so
        // the replay must be the history and nothing else. An `ESC[?1049h` left
        // in here would strand the client on an empty alternate screen.
        let mut screen = Screen::new(SIZE, 1024);

        screen.ingest(b"$ vim notes.txt\r\n");
        screen.ingest(b"\x1b[?1049h\x1b[H\x1b[2JVIM");
        screen.ingest(b"\x1b[?1049l");
        screen.ingest(b"$ ");

        assert_eq!(screen.replay(), b"$ vim notes.txt\r\n$ ");
    }
}
