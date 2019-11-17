use std::cmp::Ordering;
use std::io;
use std::net::Ipv4Addr;
use std::ops::Deref;

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use etherparse::IpTrafficClass;
use tun_tap::Iface;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum State {
    Closed,
    Listen,
    Estab,
    SynSent,
    SynRcvd,
    FinWait1,
    FinWait2,
}

/// Send Sequence Space (RFC 793  S3.2 F4)
///
///                   1         2          3          4
///              ----------|----------|----------|----------
///                     SND.UNA    SND.NXT    SND.UNA
///                                          +SND.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers of unacknowledged data
///        3 - sequence numbers allowed for new data transmission
///        4 - future sequence numbers which are not yet allowed
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}


/// Receive Sequence Space (RFC 793  S3.2 F5)
///
/// 1          2          3
/// ----------|----------|----------
/// RCV.NXT    RCV.NXT
///           +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}


/// # Connection States
/// * TCP control bits (from left to right)
/// * URG: Urgent Pointer field significant
/// * ACK: Acknowledgement field significant
/// * PSH: Push Function
/// * RST: Reset the connection
/// * SYN: Syncronize sequence numbers
/// * FIN: No more data from sender
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: Ipv4Header,
}


impl Quad {
    /// create a TCP connection 'Quad' from
    /// the headers of a tcp/ip packet
    pub fn from_headers<'a>(
        iph: &etherparse::Ipv4HeaderSlice<'a>,
        tcph: &etherparse::TcpHeaderSlice<'a>,
    ) -> Self {
        Self {
            src: (iph.source_addr(), tcph.source_port()),
            dst: (iph.destination_addr(), tcph.destination_port()),
        }
    }
}


impl Default for Connection {
    fn default() -> Self {
        Connection {
            state: State::Listen,
            send: SendSequenceSpace {
                una: 0,
                nxt: 0,
                wnd: 0,
                up: false,
                wl1: 0,
                wl2: 0,
                iss: 0,
            },
            recv: RecvSequenceSpace {
                nxt: 0,
                wnd: 0,
                up: false,
                irs: 0,
            },
            ip: Ipv4Header::default(),
        }
    }
}


impl Connection {
    pub fn accept<'a>(
        &mut self,
        nic: &'a mut Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            eprintln!("Closed->Listen flow requires an original SYN");
            return Ok(None);
        }

        // log that we've recieved a packet while listening
        println!("establishing connection {}:{} → {}:{}", iph.source_addr(), tcph.source_port(), iph.destination_addr(), tcph.destination_port());

        // on recv block, update connection info that sender just sent us
        self.recv.nxt = tcph.sequence_number() + 1;
        self.recv.irs = tcph.sequence_number();
        self.recv.wnd = tcph.window_size();

        // start establishing a response
        let mut syn_ack = TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            0,
            10,
        );

        let mut ip = Ipv4Header::new(
            syn_ack.header_len(),
            64,
            IpTrafficClass::Tcp,
            iph.destination_addr().octets(),
            iph.source_addr().octets(),
        );

        let iss: u32 = 0;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: self.send.iss,
                nxt: self.send.una + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            ip: Ipv4Header::default(),
        };

        syn_ack.acknowledgment_number = self.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        c.ip.set_payload_len(syn_ack.header_len() as usize + 0); // 0 is len of data

        let mut unwritten = &mut buf[..];
        let mut written = 0;

        let mut unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };

        nic.send(&buf[..unwritten]);
        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // acceptable ack check - https://tools.ietf.org/html/rfc793#section-3.3
        // SND.UNA < SEG.ACK =< SND.NXT - is violated if n is between u and a
        let ackn = tcph.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

        // valid segment checks
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        let datalen = data.deref().len() as u32;
        let seqn = tcph.sequence_number();
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        let start_inside_window = is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend);
        let end_inside_window = is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + datalen - 1, wend);
        if !start_inside_window && !end_inside_window {
            return Ok(());
        }

        // next, valid segment check
        match self.state {
            State::SynRcvd => {
                // we expect to get an ACK for our SYN so we can transition to established state
            }

            State::Estab => {
                unimplemented!();
            }

            _ => {}
        }

        Ok(())
    }
}

// TODO - review this
///Return bool indicating whether sequence number indicated
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // |-----s------x-----|
            // X is between S and E
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // |-----x-----s------|
            if end < start && end > x {
                // do nothing
            } else {
                return false;
            }
        }
    }
    true
}
