//! Module containing the STARTTLS flow for the IMAP protocol.

use log::debug;
use memchr::{memchr, memmem};

use stream_flows::{Io, State};

/// The STARTTLS flow that upgrades a plain IMAP (TCP) stream to an
/// encrypted one.
#[derive(Debug)]
pub struct UpgradeTls {
    step: Step,
    state: State,
}

impl UpgradeTls {
    /// The STARTTLS command.
    // TODO: make this customizable?
    const COMMAND: &str = "NGC6543 STARTTLS\r\n";

    /// Creates a new STARTTLS flow with sane defaults.
    pub fn new() -> Self {
        Self {
            step: Step::WriteStartTlsCommand,
            state: State::default(),
        }
    }

    /// Tells the flow how to handle the greeting.
    ///
    /// By default, the flow reads and discards the greeting from the
    /// plain stream. This setter may be useful if greeting has
    /// already been read before: in this case, the flow will directly
    /// write the STARTTLS command.
    ///
    /// See also [`UpgradeTls::with_discard_greeting`] for the builder
    /// alternative.
    pub fn discard_greeting(&mut self, discard: bool) {
        self.step = if discard {
            Step::DiscardGreeting(Vec::new())
        } else {
            Step::WriteStartTlsCommand
        };
    }

    /// Builder alternative to [`UpgradeTls::discard_greeting`].
    pub fn with_discard_greeting(mut self, discard: bool) -> Self {
        self.discard_greeting(discard);
        self
    }

    pub fn next(&mut self) -> Result<(), Io> {
        match (&mut self.step, self.state.take_bytes_count()) {
            (Step::DiscardGreeting(_), None) => {
                return Err(Io::Read);
            }
            (Step::DiscardGreeting(bytes), Some(n)) => {
                bytes.extend(self.state.get_read_bytes(n));

                // no new line found, keep reading
                if memchr(b'\n', bytes).is_none() {
                    return Err(Io::Read);
                };

                let bytes = String::from_utf8_lossy(bytes);
                debug!("discard greeting {bytes:?}");

                self.step = Step::WriteStartTlsCommand;
                self.state.enqueue_bytes(Self::COMMAND.as_bytes());
                debug!("enqueue command {:?}", Self::COMMAND);
                Err(Io::Write)
            }
            (Step::WriteStartTlsCommand, None) => {
                return Err(Io::Write);
            }
            (Step::WriteStartTlsCommand, Some(_)) => {
                self.step = Step::DiscardResponse(Vec::new());
                Err(Io::Read)
            }
            (Step::DiscardResponse(_), None) => {
                return Err(Io::Read);
            }
            (Step::DiscardResponse(bytes), Some(n)) => {
                bytes.extend(self.state.get_read_bytes(n));

                // no response line found, keep reading
                let Some(n) = memmem::find(bytes, b"NGC6543 ") else {
                    return Err(Io::Read);
                };

                // no new line found, keep reading
                if memchr(b'\n', &bytes[n..]).is_none() {
                    return Err(Io::Read);
                };

                let bytes = String::from_utf8_lossy(bytes);
                debug!("discard response {bytes:?}");
                Ok(())
            }
        }
    }
}

impl AsMut<State> for UpgradeTls {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

/// Internal state of the [`UpgradeTls`] flow.
#[derive(Debug)]
enum Step {
    /// The greeting needs to be discarded.
    DiscardGreeting(Vec<u8>),

    /// The STARTTLS command needs to be written.
    WriteStartTlsCommand,

    /// The STARTTLS response needs to be discarded.
    DiscardResponse(Vec<u8>),
}
