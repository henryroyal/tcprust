use std::io;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::ops::Deref;

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use etherparse::IpTrafficClass;
use tun_tap::Iface;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

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
            send: SendSequenceSpace,
            recv: RecvSequenceSpace,
            ip: Ipv4Header,
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
            !eprintln!("Closed->Listen flow requires an original SYN");
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
            dport,
            sport,
            0,
            10,
        );

        let mut ip = Ipv4Header::new(
            syn_ack.header_len(),
            64,
            IpTrafficClass::Tcp,
            dst.octets(),
            src.octets(),
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
            ip: Ipv4Header::new(),
        };

        syn_ack.acknowledgment_number = self.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        c.ip.set_payload_len(syn_ack.header_len() as usize + 0); // 0 is len of data

        let mut unwritten = &mut buf[..];
        let mut written = 0;

        let mut unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(unwritten);
            syn_ack.write(unwritten);
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
        // first, acceptable ack check - https://tools.ietf.org/html/rfc793#section-3.3
        // SND.UNA < SEG.ACK =< SND.NXT - is violated if n is between u and a
        let ackn = tcph.acknowledgment_number();
        if self.send.una < ack {
            // this is the easy case where no wraparound
        } else {
            // n may have wrapped -- check that n is not between a and u
            if self.send.nxt >= ackn && self.send.nxt <= self.send.una { // fine
            } else {
                return Ok(());
            }
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


fn is_between_wrapped(start: usize, x: usize, end: usize) -> bool {
    if start < x {
        if end >= start && end < x { return true; }
    } else {}

    false
}
