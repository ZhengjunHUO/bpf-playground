use anyhow::bail;
use anyhow::Result;
use libbpf_rs::MapFlags;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::TC_CUSTOM;
use libbpf_rs::TC_EGRESS;
use libbpf_rs::TC_H_CLSACT;
use libbpf_rs::TC_H_MIN_INGRESS;
use libbpf_rs::TC_INGRESS;
use std::net::Ipv4Addr;

mod tc {
    include!(concat!(env!("OUT_DIR"), "/tc_fw.skel.rs"));
}
use tc::*;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let builder = TcFwSkelBuilder::default();
    let open = builder.open()?;
    let mut skel = open.load()?;
    let progs = skel.progs();
    let ifidx = nix::net::if_::if_nametoindex("vetha86e559")? as i32;

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(progs.tc_filter().fd())
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS).handle(2);

    let mut maps = skel.maps_mut();
    let ing_fw_map = maps.ingress_blacklist();
    let key = ipv4_to_u32("172.17.0.2")?;
    let value = u8::from(true).to_ne_bytes();
    ing_fw_map.update(&key, &value, MapFlags::ANY)?;

    ingress.create()?;

    if let Err(e) = egress.attach() {
        println!("failed to attach egress hook {e}");
    }

    if let Err(e) = ingress.attach() {
        println!("failed to attach ingress hook {e}");
    }

    if let Err(e) = custom.attach() {
        println!("failed to attach custom hook {e}");
    }

    Ok(())
}

fn ipv4_to_u32(ip: &str) -> Result<[u8; 4]> {
    use std::str::FromStr;

    let ip_parsed = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(ip_parsed).to_be_bytes())
}
