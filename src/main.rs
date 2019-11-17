use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use tun_tap::{Iface, Mode};

use crate::tcp::Quad;

pub mod tcp;

fn main() -> io::Result<()> {
    let mut buf = [0u8; 1504];
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = Default::default();

    let mut nic = Iface::without_packet_info("tun0", Mode::Tun)
        .expect("Failed to initialize tun0 interface");
    eprint!("created interface {} in {:?} mode\n", nic.name(), nic.mode());

    loop {
        let nbytes: usize = nic.recv(&mut buf[..])?;

        match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    // not tcp
                    continue;
                }

                match TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        let datai = iph.slice().len() + tcph.slice().len();

                        match connections.entry(
                            Quad {
                                src: (src, tcph.destination_port()),
                                dst: (dst, tcph.destination_port()),
                            }) {
                            Entry::Occupied(mut oe) => {
                                if let Err(e) = oe.get_mut().on_packet(&mut nic, iph, tcph, &buf[datai..nbytes]) {
                                    eprintln!("Error: {}", e);
                                } else {
                                    eprintln!("Packet {:?}", &buf[..]);
                                }
                            }

                            Entry::Vacant(mut ve) => {
                                if let Some(c) = tcp::Connection::default().accept(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )?
                                {
                                    eprintln!("Accept: {:?}", c);
                                    ve.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("TcpHeader parsing error: {:?}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Ipv4Header parsing error: {:?}", e);
                continue;
            }
        }
    }

    // Ok(())
}
