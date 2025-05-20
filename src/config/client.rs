#![allow(unsafe_code)]

use super::{
    dns::{DnsCache, ResolveMap},
    request::SetOpt,
};
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Debug, Default)]
pub(crate) struct ClientConfig {
    pub(crate) connection_cache_ttl: Option<Duration>,
    pub(crate) close_connections: bool,
    pub(crate) dns_cache: Option<DnsCache>,
    pub(crate) dns_resolve: Option<ResolveMap>,
    pub(crate) dns_servers: Option<String>,
    pub(crate) ip_blacklist: Option<IpBlacklist>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpBlacklist {
    pub(crate) ipv4: IpRange<Ipv4Net>,
    pub(crate) ipv6: IpRange<Ipv6Net>,
}

unsafe extern "C" fn handler(
    data: *mut std::ffi::c_void,
    _purpose: curl_sys::curlsocktype,
    address: *mut curl_sys::curl_sockaddr,
) -> curl_sys::curl_socket_t {
    (*((&(*address).addr) as *const libc::sockaddr as *const libc::sockaddr_in6)).sin6_addr;
    let ip = match (*address).family {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::from_bits(
            (*((&(*address).addr) as *const libc::sockaddr as *const libc::sockaddr_in))
                .sin_addr
                .s_addr
                .to_be(),
        ))
        .into(),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from_bits(
            (*(&((*((&(*address).addr) as *const libc::sockaddr as *const libc::sockaddr_in6))
                .sin6_addr
                .s6_addr) as *const u8 as *const u128))
                .to_be(),
        ))
        .into(),
        _ => None,
    };

    let Some(ip) = ip else {
        return curl_sys::CURL_SOCKET_BAD;
    };

    let blocked_ranges: &IpBlacklist = &*(data as *const IpBlacklist);

    let blocked = match &ip {
        IpAddr::V4(ipv4_addr) => blocked_ranges.ipv4.contains(ipv4_addr),
        IpAddr::V6(ipv6_addr) => blocked_ranges.ipv6.contains(ipv6_addr),
    };

    if blocked {
        return curl_sys::CURL_SOCKET_BAD;
    }

    return socket2::Socket::new(
        (*address).family.into(),
        (*address).socktype.into(),
        Some((*address).protocol.into()),
    )
    .ok()
    .map(cvt)
    .unwrap_or(curl_sys::CURL_SOCKET_BAD);

    #[cfg(unix)]
    fn cvt(socket: socket2::Socket) -> curl_sys::curl_socket_t {
        use std::os::unix::prelude::*;
        socket.into_raw_fd()
    }
}

impl SetOpt for ClientConfig {
    fn set_opt<H>(&self, easy: &mut curl::easy::Easy2<H>) -> Result<(), curl::Error> {
        if let Some(ttl) = self.connection_cache_ttl {
            easy.maxage_conn(ttl)?;
        }

        if let Some(cache) = self.dns_cache.as_ref() {
            cache.set_opt(easy)?;
        }

        if let Some(map) = self.dns_resolve.as_ref() {
            map.set_opt(easy)?;
        }

        if let Some(dns_servers) = &self.dns_servers {
            easy.dns_servers(dns_servers)?;
        }

        if let Some(ip_blacklist) = &self.ip_blacklist {
            easy.open_socket_function(handler)?;
            easy.open_socket_data(ip_blacklist as *const IpBlacklist as *mut std::ffi::c_void)?;
        }

        easy.forbid_reuse(self.close_connections)
    }
}
