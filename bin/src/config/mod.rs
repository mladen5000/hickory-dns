// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Configuration module for the server binary, `hickory-dns`.

#[cfg(feature = "__tls")]
use std::ffi::OsStr;
#[cfg(feature = "prometheus-metrics")]
use std::net::SocketAddr;
use std::{
    fmt, fs, io,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "sqlite")]
use cfg_if::cfg_if;
use ipnet::IpNet;
#[cfg(feature = "__tls")]
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{self, Deserialize, Deserializer};
use thiserror::Error;
use tracing::{debug, info};

#[cfg(feature = "__dnssec")]
use crate::dnssec;
#[cfg(feature = "__https")]
use hickory_net::http::DEFAULT_DNS_QUERY_PATH;
#[cfg(feature = "__tls")]
use hickory_net::tls::default_provider;
use hickory_proto::{ProtoError, rr::Name, serialize::txt::ParseError};
#[cfg(feature = "recursor")]
use hickory_resolver::recursor::RecursiveConfig;
#[cfg(feature = "__dnssec")]
use hickory_server::dnssec::NxProofKind;
#[cfg(any(feature = "recursor", feature = "sqlite"))]
use hickory_server::net::runtime::TokioRuntimeProvider;
#[cfg(feature = "blocklist")]
use hickory_server::store::blocklist::{BlocklistConfig, BlocklistZoneHandler};
#[cfg(feature = "resolver")]
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
#[cfg(feature = "recursor")]
use hickory_server::store::recursor::RecursiveZoneHandler;
#[cfg(feature = "sqlite")]
use hickory_server::store::sqlite::{SqliteConfig, SqliteZoneHandler};
use hickory_server::{
    store::file::{FileConfig, FileZoneHandler},
    zone_handler::{AxfrPolicy, ZoneHandler, ZoneType},
};

#[cfg(test)]
mod tests;

/// Server configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub(crate) struct Config {
    /// The list of IPv4 addresses to listen on
    #[serde(default)]
    pub(crate) listen_addrs_ipv4: Vec<Ipv4Addr>,
    /// This list of IPv6 addresses to listen on
    #[serde(default)]
    pub(crate) listen_addrs_ipv6: Vec<Ipv6Addr>,
    /// Port on which to listen (associated to all IPs)
    #[serde(default = "default_port")]
    pub(crate) listen_port: u16,
    /// Secure port to listen on
    #[cfg(feature = "__tls")]
    #[serde(default = "default_tls_port")]
    pub(crate) tls_listen_port: u16,
    /// HTTPS port to listen on
    #[cfg(feature = "__https")]
    #[serde(default = "default_https_port")]
    pub(crate) https_listen_port: u16,
    /// QUIC port to listen on
    #[cfg(feature = "__quic")]
    #[serde(default = "default_tls_port")]
    pub(crate) quic_listen_port: u16,
    /// Prometheus listen address
    #[cfg(feature = "prometheus-metrics")]
    pub(crate) prometheus_listen_addr: Option<SocketAddr>,
    /// Disable TCP protocol
    #[serde(default)]
    pub(crate) disable_tcp: bool,
    /// Disable UDP protocol
    #[serde(default)]
    pub(crate) disable_udp: bool,
    /// Disable TLS protocol
    #[cfg(feature = "__tls")]
    #[serde(default)]
    pub(crate) disable_tls: bool,
    /// Disable HTTPS protocol
    #[cfg(feature = "__https")]
    #[serde(default)]
    pub(crate) disable_https: bool,
    /// Disable QUIC protocol
    #[cfg(feature = "__quic")]
    #[serde(default)]
    pub(crate) disable_quic: bool,
    /// Disable Prometheus metrics
    #[cfg(feature = "prometheus-metrics")]
    #[serde(default)]
    pub(crate) disable_prometheus: bool,
    /// Timeout associated to a request before it is closed.
    #[serde(
        deserialize_with = "parse_request_timeout",
        default = "default_request_timeout"
    )]
    pub(crate) tcp_request_timeout: Duration,
    /// Whether to respect the SSLKEYLOGFILE environment variable.
    ///
    /// This should only be enabled WITH CARE! When enabled, and the SSLKEYLOGFILE environment
    /// variable is set, TLS session keys will be logged to the filepath specified by the
    /// environment variable value.
    ///
    /// This is principally useful for decrypting captured packet data with tools like Wireshark.
    #[cfg(feature = "__tls")]
    #[serde(default)]
    pub(crate) ssl_keylog_enabled: bool,
    /// Base configuration directory, i.e. root path for zones
    #[serde(default = "default_directory")]
    pub(crate) directory: PathBuf,
    /// User to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this user (or to nobody if no user is specified here.)
    pub user: Option<String>,
    /// Group to run the server as.
    ///
    /// Only supported on Unix-like platforms. If the real or effective UID of the hickory process
    /// is root, we will attempt to change to this group (or to nobody if no group is specified here.)
    pub group: Option<String>,
    /// List of configurations for zones
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_file")]
    pub(crate) zones: Vec<ZoneConfig>,
    /// Certificate to associate to TLS connections (currently the same is used for HTTPS and TLS)
    #[cfg(feature = "__tls")]
    pub(crate) tls_cert: Option<TlsCertConfig>,
    /// The HTTP endpoint where the DNS-over-HTTPS server provides service. Applicable
    /// to both HTTP/2 and HTTP/3 servers. Typically `/dns-query`.
    #[cfg(feature = "__https")]
    #[serde(default = "default_http_endpoint")]
    pub(crate) http_endpoint: String,
    /// Networks denied access to the server.
    ///
    /// Requests originating from any of these CIDRs are rejected. If
    /// `allow_networks` is also set, it acts as an override list: an address
    /// matched by both is allowed.
    #[serde(default)]
    pub(crate) deny_networks: Vec<IpNet>,
    /// Networks allowed to access the server.
    ///
    /// When non-empty, requests not originating from any of these CIDRs are
    /// rejected (the server effectively operates as an allow-list). When
    /// combined with `deny_networks`, entries here override matching deny
    /// entries.
    #[serde(default)]
    pub(crate) allow_networks: Vec<IpNet>,
    /// UDP socket configuration options.
    #[serde(default)]
    pub(crate) udp_socket: UdpSocketConfig,
    /// TCP socket configuration options.
    #[serde(default)]
    pub(crate) tcp_socket: TcpSocketConfig,
}

/// Configuration options for UDP sockets.
///
/// These settings control the kernel buffer sizes for UDP sockets used by the DNS server.
/// Under high query load, increasing buffer sizes can help prevent packet loss when the
/// application cannot process incoming packets fast enough.
///
/// Note: The kernel may cap the actual buffer size based on system limits
/// (e.g., `net.core.rmem_max` on Linux). Check logs at startup to see the actual
/// buffer size that was configured.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UdpSocketConfig {
    /// UDP socket receive buffer size in bytes.
    ///
    /// Controls the kernel buffer for incoming UDP packets. If not specified, the operating
    /// system default is used. Larger values help absorb traffic bursts without dropping
    /// packets.
    pub(crate) recv_buffer_size: Option<usize>,
    /// UDP socket send buffer size in bytes.
    ///
    /// Controls the kernel buffer for outgoing UDP packets. If not specified, the operating
    /// system default is used. Larger values help when the server is sending many responses.
    pub(crate) send_buffer_size: Option<usize>,
    /// Number of UDP sockets to create per listen address (Unix only).
    ///
    /// Using multiple sockets with SO_REUSEPORT allows the kernel to distribute incoming packets
    /// across sockets, which may improve performance under high load. Optimal values depend
    /// on workload and setting it too high will have the opposite effect and cause performance
    /// degradation.
    ///
    /// Defaults to 1.
    #[cfg(unix)]
    pub(crate) sockets: Option<usize>,
}

/// Configuration options for TCP sockets.
///
/// These settings control aspects of TCP listeners used by the DNS server.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TcpSocketConfig {
    /// TCP listen backlog size.
    ///
    /// Controls the maximum number of pending connections queued by the kernel before
    /// connections are refused. If not specified, defaults to 128.
    ///
    /// Higher values allow more connections to queue during traffic spikes.
    /// Consider increasing this for high-TCP load deployments.
    ///
    /// On Linux the kernel `net.core.somaxconn` and `net.ipv[4|6].tcp_max_syn_backlog`
    /// may also need adjustment to match.
    #[serde(default = "default_tcp_listen_backlog")]
    pub(crate) listen_backlog: i32,

    /// TCP response buffer size.
    ///
    /// Controls the maximum number of DNS responses that can be queued for
    /// sending on a single TCP connection. Under high query rates, a larger
    /// buffer prevents responses from being dropped due to backpressure.
    ///
    /// If not specified, defaults to 32.
    #[serde(default = "default_tcp_response_buffer_size")]
    pub(crate) response_buffer_size: usize,
}

impl Default for TcpSocketConfig {
    fn default() -> Self {
        Self {
            listen_backlog: default_tcp_listen_backlog(),
            response_buffer_size: default_tcp_response_buffer_size(),
        }
    }
}

fn default_tcp_listen_backlog() -> i32 {
    128
}

fn default_tcp_response_buffer_size() -> usize {
    32
}

/// Maximum number of entries we'll accept for any single resolver cache
/// (recursor or forwarder).
///
/// Past this, an integer-overflow-large value (or a typo like `1048576000000`)
/// would silently allocate gigabytes at first request and OOM the process.
/// 16M entries is generous — at ~200 bytes per cached DNS response that is
/// still ~3GB of resident memory, which is well past any realistic deployment.
#[cfg(any(feature = "recursor", feature = "resolver"))]
const MAX_RESOLVER_CACHE_ENTRIES: u64 = 1 << 24;

#[cfg(unix)]
pub(crate) const MAX_UDP_SOCKETS: usize = 256;

impl Config {
    /// read a Config file from the file specified at path.
    pub(crate) fn read_config(path: &Path) -> Result<Self, ConfigError> {
        let config = Self::from_toml(&fs::read_to_string(path)?)?;
        config.check_directory_traversal()?;
        config.check_open_recursor()?;
        #[cfg(any(feature = "recursor", feature = "resolver"))]
        config.check_cache_caps()?;
        #[cfg(unix)]
        config.check_udp_socket_caps()?;
        Ok(config)
    }

    /// Reject `..` components in the `directory` field, which is the base for
    /// every other relative path in the config. Absolute paths are allowed
    /// (operators legitimately point `directory` at `/var/named` or similar).
    fn check_directory_traversal(&self) -> Result<(), ConfigError> {
        Self::check_directory_path(&self.directory, "directory")
    }

    pub(crate) fn check_directory_path(
        path: &Path,
        field: &'static str,
    ) -> Result<(), ConfigError> {
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(ConfigError::DirectoryTraversal {
                field,
                path: path.display().to_string(),
            });
        }
        Ok(())
    }

    /// Read a [`Config`] from the given TOML string.
    fn from_toml(toml: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(toml)?)
    }

    #[cfg(unix)]
    fn check_udp_socket_caps(&self) -> Result<(), ConfigError> {
        if let Some(sockets) = self.udp_socket.sockets {
            if sockets > MAX_UDP_SOCKETS {
                return Err(ConfigError::UdpSocketCountTooLarge {
                    value: sockets,
                    max: MAX_UDP_SOCKETS,
                });
            }
        }
        Ok(())
    }

    /// Reject configurations that would expose a recursive or forwarding
    /// resolver to the public internet with no client ACL.
    ///
    /// A recursor reachable by arbitrary clients can be used for amplification
    /// DDoS attacks and is the kind of misconfiguration that almost always
    /// indicates an operator mistake. We block this at parse time so the error
    /// surfaces before any port is bound.
    ///
    /// The check fires when *all* of the following hold:
    ///   * at least one zone uses a `recursor` or `forward` store;
    ///   * `allow_networks` is empty (no client allow-list);
    ///   * at least one listen address is not loopback (or the listen lists
    ///     are empty, which defaults to binding 0.0.0.0 and ::).
    fn check_open_recursor(&self) -> Result<(), ConfigError> {
        if !self.allow_networks.is_empty() {
            return Ok(());
        }

        let has_resolver_zone = self.zones.iter().any(|z| {
            let ZoneTypeConfig::External { stores } = &z.zone_type_config else {
                return false;
            };
            stores.iter().any(is_resolver_store)
        });
        if !has_resolver_zone {
            return Ok(());
        }

        let listens_anywhere_non_loopback = self.listen_addrs_ipv4.is_empty()
            && self.listen_addrs_ipv6.is_empty()
            || self.listen_addrs_ipv4.iter().any(|a| !a.is_loopback())
            || self.listen_addrs_ipv6.iter().any(|a| !a.is_loopback());

        if listens_anywhere_non_loopback {
            return Err(ConfigError::OpenRecursor);
        }
        Ok(())
    }

    /// Reject resolver-side cache sizes large enough to be obvious mistakes.
    /// Covers the recursor (ns/response/validation caches) and the forwarder
    /// (resolver cache_size). See [`MAX_RESOLVER_CACHE_ENTRIES`].
    #[cfg(any(feature = "recursor", feature = "resolver"))]
    fn check_cache_caps(&self) -> Result<(), ConfigError> {
        #[cfg(all(feature = "recursor", feature = "__dnssec"))]
        use hickory_resolver::recursor::DnssecPolicyConfig;

        let check = |field: &'static str, value: u64| -> Result<(), ConfigError> {
            if value > MAX_RESOLVER_CACHE_ENTRIES {
                Err(ConfigError::CacheSizeTooLarge {
                    field,
                    value,
                    max: MAX_RESOLVER_CACHE_ENTRIES,
                })
            } else {
                Ok(())
            }
        };

        for zone in &self.zones {
            let ZoneTypeConfig::External { stores } = &zone.zone_type_config else {
                continue;
            };
            for store in stores {
                match store {
                    #[cfg(feature = "recursor")]
                    ExternalStoreConfig::Recursor(cfg) => {
                        check("ns_cache_size", cfg.options.ns_cache_size as u64)?;
                        check("response_cache_size", cfg.options.response_cache_size)?;
                        #[cfg(feature = "__dnssec")]
                        if let DnssecPolicyConfig::ValidateWithStaticKey {
                            validation_cache_size: Some(size),
                            ..
                        } = &cfg.dnssec_policy
                        {
                            check("validation_cache_size", *size as u64)?;
                        }
                    }
                    #[cfg(feature = "resolver")]
                    ExternalStoreConfig::Forward(cfg) => {
                        if let Some(opts) = &cfg.options {
                            check("forward.cache_size", opts.cache_size)?;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct ZoneConfigWithFile {
    file: Option<PathBuf>,
    #[serde(flatten)]
    config: ZoneConfig,
}

fn deserialize_with_file<'de, D>(deserializer: D) -> Result<Vec<ZoneConfig>, D::Error>
where
    D: Deserializer<'de>,
    D::Error: de::Error,
{
    Vec::<ZoneConfigWithFile>::deserialize(deserializer)?
        .into_iter()
        .map(|ZoneConfigWithFile { file, mut config }| match file {
            Some(file) => match &mut config.zone_type_config {
                ZoneTypeConfig::Primary(server_config)
                | ZoneTypeConfig::Secondary(server_config) => {
                    if server_config
                        .stores
                        .iter()
                        .any(|store| matches!(store, ServerStoreConfig::File(_)))
                    {
                        Err(<D::Error as de::Error>::custom(
                            "having `file` and `[zones.store]` item with type `file` is ambiguous",
                        ))
                    } else {
                        let store = ServerStoreConfig::File(FileConfig { zone_path: file });

                        if server_config.stores.len() == 1
                            && matches!(&server_config.stores[0], ServerStoreConfig::Default)
                        {
                            server_config.stores[0] = store;
                        } else {
                            server_config.stores.push(store);
                        }
                        Ok(config)
                    }
                }
                _ => Err(<D::Error as de::Error>::custom(
                    "cannot use `file` on a zone that is not primary or secondary",
                )),
            },

            _ => Ok(config),
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Configuration for a zone
#[derive(Deserialize, Debug)]
pub(crate) struct ZoneConfig {
    /// name of the zone
    pub zone: String, // TODO: make Domain::Name decodable
    /// type of the zone
    #[serde(flatten)]
    pub zone_type_config: ZoneTypeConfig,
}

impl ZoneConfig {
    /// Load this zone's handlers. When `validate_only` is true, side-effecting
    /// stores (currently `recursor`, which spawns a persistence task and may
    /// write state files) are skipped with an info log instead. All other
    /// stores still parse their backing files so missing-file errors surface
    /// at `--validate` time.
    pub(crate) async fn load_with_mode(
        self,
        zone_dir: &Path,
        validate_only: bool,
    ) -> Result<Vec<Arc<dyn ZoneHandler>>, ProtoError> {
        debug!("loading zone with config: {self:#?}");

        let zone_name = self
            .zone()
            .map_err(|err| format!("failed to read zone name: {err}"))?;
        let zone_type = self.zone_type();

        // load the zone and insert any configured zone handlers in the catalog.

        let mut handlers: Vec<Arc<dyn ZoneHandler>> = vec![];
        match self.zone_type_config {
            ZoneTypeConfig::Primary(server_config) | ZoneTypeConfig::Secondary(server_config) => {
                debug!(
                    "loading zone handlers for {zone_name} with stores {:?}",
                    server_config.stores
                );

                let axfr_policy = server_config.axfr_policy();
                for store in &server_config.stores {
                    let handler: Arc<dyn ZoneHandler> = match store {
                        #[cfg(feature = "sqlite")]
                        ServerStoreConfig::Sqlite(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut handler =
                                SqliteZoneHandler::<TokioRuntimeProvider>::try_from_config(
                                    zone_name.clone(),
                                    zone_type,
                                    axfr_policy,
                                    server_config.is_dnssec_enabled(),
                                    Some(zone_dir),
                                    config,
                                    #[cfg(feature = "__dnssec")]
                                    server_config.nx_proof_kind.clone(),
                                )
                                .await?;

                            #[cfg(feature = "__dnssec")]
                            dnssec::load_keys(
                                &mut handler,
                                &zone_name,
                                zone_dir,
                                &server_config.keys,
                            )
                            .await?;
                            Arc::new(handler)
                        }

                        ServerStoreConfig::File(config) => {
                            #[cfg_attr(not(feature = "__dnssec"), allow(unused_mut))]
                            let mut handler = FileZoneHandler::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                axfr_policy,
                                Some(zone_dir),
                                config,
                                #[cfg(feature = "__dnssec")]
                                server_config.nx_proof_kind.clone(),
                            )?;

                            #[cfg(feature = "__dnssec")]
                            dnssec::load_keys(
                                &mut handler,
                                &zone_name,
                                zone_dir,
                                &server_config.keys,
                            )
                            .await?;
                            Arc::new(handler)
                        }
                        _ => return Err(ProtoError::from(EMPTY_STORES)),
                    };

                    handlers.push(handler);
                }
            }
            ZoneTypeConfig::External { stores } => {
                debug!(
                    "loading zone handlers for {zone_name} with stores {:?}",
                    stores
                );

                #[cfg_attr(
                    not(any(feature = "blocklist", feature = "resolver")),
                    allow(unreachable_code, unused_variables, clippy::never_loop)
                )]
                for store in stores {
                    let handler: Arc<dyn ZoneHandler> = match store {
                        #[cfg(feature = "blocklist")]
                        ExternalStoreConfig::Blocklist(config) => {
                            Arc::new(BlocklistZoneHandler::try_from_config(
                                zone_name.clone(),
                                config,
                                Some(zone_dir),
                            )?)
                        }
                        #[cfg(feature = "resolver")]
                        ExternalStoreConfig::Forward(config) => {
                            let forwarder = ForwardZoneHandler::builder_tokio(config)
                                .with_origin(zone_name.clone())
                                .build()?;

                            Arc::new(forwarder)
                        }
                        #[cfg(feature = "recursor")]
                        ExternalStoreConfig::Recursor(config) => {
                            if validate_only {
                                info!(
                                    "skipping recursor store for {zone_name} in --validate mode \
                                     (avoids spawning persistence task and writing state files)"
                                );
                                continue;
                            }
                            let recursor = RecursiveZoneHandler::try_from_config(
                                zone_name.clone(),
                                zone_type,
                                *config,
                                Some(zone_dir),
                                TokioRuntimeProvider::default(),
                            )
                            .await?;

                            Arc::new(recursor)
                        }
                        _ => return Err(ProtoError::from(EMPTY_STORES)),
                    };

                    handlers.push(handler);
                }
            }
        }

        info!("zone successfully loaded: {zone_name}");
        Ok(handlers)
    }

    // TODO this is a little ugly for the parse, b/c there is no terminal char
    /// returns the name of the Zone, i.e. the `example.com` of `www.example.com.`
    pub(crate) fn zone(&self) -> Result<Name, ProtoError> {
        Name::parse(&self.zone, Some(&Name::new()))
    }

    /// the type of the zone
    fn zone_type(&self) -> ZoneType {
        match &self.zone_type_config {
            ZoneTypeConfig::Primary { .. } => ZoneType::Primary,
            ZoneTypeConfig::Secondary { .. } => ZoneType::Secondary,
            ZoneTypeConfig::External { .. } => ZoneType::External,
        }
    }
}

const EMPTY_STORES: &str = "empty [[zones.stores]] in config";

#[derive(Deserialize, Debug)]
#[serde(tag = "zone_type")]
#[serde(deny_unknown_fields)]
/// Enumeration over each zone type's configuration.
pub(crate) enum ZoneTypeConfig {
    Primary(ServerZoneConfig),
    Secondary(ServerZoneConfig),
    External {
        /// Store configurations.  Note: we specify a default handler to get a Vec containing a
        /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
        /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
        /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
        /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
        #[serde(default = "store_config_default")]
        #[serde(deserialize_with = "store_config_visitor")]
        stores: Vec<ExternalStoreConfig>,
    },
}

impl ZoneTypeConfig {
    #[cfg(test)]
    fn as_server(&self) -> Option<&ServerZoneConfig> {
        match self {
            Self::Primary(c) | Self::Secondary(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerZoneConfig {
    /// A policy used to determine whether AXFR requests are allowed
    ///
    /// By default, all AXFR requests are rejected
    #[serde(default)]
    pub axfr_policy: AxfrPolicy,
    /// Keys for use by the zone
    #[cfg(feature = "__dnssec")]
    #[serde(default)]
    pub keys: Vec<dnssec::KeyConfig>,
    /// The kind of non-existence proof provided by the nameserver
    #[cfg(feature = "__dnssec")]
    pub nx_proof_kind: Option<NxProofKind>,
    /// Store configurations.  Note: we specify a default handler to get a Vec containing a
    /// StoreConfig::Default, which is used for authoritative file-based zones and legacy sqlite
    /// configurations. #[serde(default)] cannot be used, because it will invoke Default for Vec,
    /// i.e., an empty Vec and we cannot implement Default for StoreConfig and return a Vec.  The
    /// custom visitor is used to handle map (single store) or sequence (chained store) configurations.
    #[serde(default = "store_config_default")]
    #[serde(deserialize_with = "store_config_visitor")]
    pub stores: Vec<ServerStoreConfig>,
}

impl ServerZoneConfig {
    /// path to the zone file, i.e. the base set of original records in the zone
    ///
    /// this is only used on first load, if dynamic update is enabled for the zone, then the journal
    /// file is the actual source of truth for the zone.
    #[cfg(test)]
    fn file(&self) -> Option<&Path> {
        self.stores.iter().find_map(|store| match store {
            ServerStoreConfig::File(file_config) => Some(&*file_config.zone_path),
            #[cfg(feature = "sqlite")]
            ServerStoreConfig::Sqlite(sqlite_config) => Some(&*sqlite_config.zone_path),
            ServerStoreConfig::Default => None,
        })
    }

    /// Return a policy that can be used to determine how AXFR requests should be handled.
    fn axfr_policy(&self) -> AxfrPolicy {
        self.axfr_policy
    }

    /// declare that this zone should be signed, see keys for configuration of the keys for signing
    #[cfg(feature = "sqlite")]
    fn is_dnssec_enabled(&self) -> bool {
        cfg_if! {
            if #[cfg(feature = "__dnssec")] {
                !self.keys.is_empty()
            } else {
                false
            }
        }
    }
}

/// Enumeration over store types for secondary nameservers.
#[derive(Deserialize, Debug, Default)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub(crate) enum ServerStoreConfig {
    /// File based configuration
    File(FileConfig),
    /// Sqlite based configuration file
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteConfig),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Enumeration over store types for external nameservers.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
#[non_exhaustive]
pub(crate) enum ExternalStoreConfig {
    /// Blocklist configuration
    #[cfg(feature = "blocklist")]
    Blocklist(BlocklistConfig),
    /// Forwarding Resolver
    #[cfg(feature = "resolver")]
    Forward(ForwardConfig),
    /// Recursive Resolver
    #[cfg(feature = "recursor")]
    Recursor(Box<RecursiveConfig>),
    /// This is used by the configuration processing code to represent a deprecated or main-block config without an associated store.
    #[default]
    Default,
}

/// Create a default value for serde for store config enums.
fn store_config_default<S: Default>() -> Vec<S> {
    vec![Default::default()]
}

/// Custom serde visitor that can deserialize a map (single configuration store, expressed as a TOML
/// table) or sequence (chained configuration stores, expressed as a TOML array of tables.)
/// This is used instead of an untagged enum because serde cannot provide variant-specific error
/// messages when using an untagged enum.
fn store_config_visitor<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapOrSequence<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOrSequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("map or sequence")
        }

        fn visit_seq<S>(self, seq: S) -> Result<Vec<T>, S::Error>
        where
            S: SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }

        fn visit_map<M>(self, map: M) -> Result<Vec<T>, M::Error>
        where
            M: MapAccess<'de>,
        {
            match Deserialize::deserialize(de::value::MapAccessDeserializer::new(map)) {
                Ok(seq) => Ok(vec![seq]),
                Err(e) => Err(e),
            }
        }
    }

    deserializer.deserialize_any(MapOrSequence::<T>(PhantomData))
}

/// Configuration for a TLS certificate
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub(crate) struct TlsCertConfig {
    pub(crate) path: PathBuf,
    pub(crate) endpoint_name: Option<String>,
    pub(crate) private_key: PathBuf,
}

#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
impl TlsCertConfig {
    /// Load a Certificate from the path (with rustls)
    pub(crate) fn load(&self, zone_dir: &Path) -> Result<Arc<dyn ResolvesServerCert>, String> {
        if let Some(endpoint_name) = &self.endpoint_name {
            info!("loading TLS cert for {endpoint_name} from {:?}", self.path);
        } else {
            info!("loading TLS cert from {:?}", self.path);
        }

        if self.path.extension().and_then(OsStr::to_str) != Some("pem") {
            return Err(format!(
                "unsupported certificate file format (expected `.pem` extension): {}",
                self.path.display()
            ));
        }

        reject_parent_dir_components(&self.path, "tls_cert.path")?;
        reject_parent_dir_components(&self.private_key, "tls_cert.private_key")?;

        let cert_path = zone_dir.join(&self.path);
        info!(
            "loading TLS PEM certificate chain from: {}",
            cert_path.display()
        );

        let cert_chain = CertificateDer::pem_file_iter(&cert_path)
            .map_err(|e| {
                format!(
                    "failed to read cert chain from {}: {e}",
                    cert_path.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                format!(
                    "failed to parse cert chain from {}: {e}",
                    cert_path.display()
                )
            })?;

        let key_extension = self.private_key.extension();
        let key = if key_extension.is_some_and(|ext| ext == "pem") {
            let key_path = zone_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from PEM: {}", key_path.display());
            PrivateKeyDer::from_pem_file(&key_path)
                .map_err(|e| format!("failed to read key from {}: {e}", key_path.display()))?
        } else if key_extension.is_some_and(|ext| ext == "der" || ext == "key") {
            let key_path = zone_dir.join(&self.private_key);
            info!("loading TLS PKCS8 key from DER: {}", key_path.display());

            let buf =
                fs::read(&key_path).map_err(|e| format!("error reading key from file: {e}"))?;
            PrivateKeyDer::try_from(buf).map_err(|e| format!("error parsing key DER: {e}"))?
        } else {
            return Err(format!(
                "unsupported private key file format (expected `.pem` or `.der` extension): {}",
                self.private_key.display()
            ));
        };

        let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())
            .map_err(|err| format!("failed to read certificate and keys: {err:?}"))?;

        Ok(Arc::new(SingleCertAndKey::from(certified_key)))
    }
}

/// Whether the given store represents recursive or forwarding resolution,
/// i.e. the kinds of stores that turn the binary into a public-amplification
/// risk if exposed without an ACL.
fn is_resolver_store(store: &ExternalStoreConfig) -> bool {
    match store {
        #[cfg(feature = "recursor")]
        ExternalStoreConfig::Recursor(_) => true,
        #[cfg(feature = "resolver")]
        ExternalStoreConfig::Forward(_) => true,
        _ => false,
    }
}

/// Reject paths that contain `..` components.
///
/// Absolute paths are allowed (operators legitimately point at e.g. ACME-managed
/// directories outside `zone_dir`), but parent-dir traversal in a relative path
/// is never intentional — it usually indicates a confused-deputy or templated
/// config that escaped its intended sandbox.
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
fn reject_parent_dir_components(path: &Path, field: &str) -> Result<(), String> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "{field} must not contain `..` components: {}",
            path.display()
        ));
    }
    Ok(())
}

/// The error kind for errors that get returned in the crate
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum ConfigError {
    // foreign
    /// An error got returned from IO
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// An error occurred while decoding toml data
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),

    /// An error occurred while parsing a zone file
    #[error("failed to parse the zone file: {0}")]
    ZoneParse(#[from] ParseError),

    /// The configuration would expose a recursor or forwarder to arbitrary
    /// clients with no allow_networks list.
    #[error(
        "refusing to start: recursor or forwarder listens on non-loopback addresses with no \
         `allow_networks` set — this would create an open public resolver. Set `allow_networks` \
         to the prefixes you intend to serve, or bind only to loopback."
    )]
    OpenRecursor,

    /// A recursor cache size field is larger than is plausibly intentional.
    #[cfg(feature = "recursor")]
    #[error(
        "{field} = {value} exceeds the maximum of {max} entries; a value this large is almost \
         certainly a typo and would cause large up-front allocations"
    )]
    CacheSizeTooLarge {
        field: &'static str,
        value: u64,
        max: u64,
    },

    /// The configured directory field contains `..` components.
    #[error(
        "`{field}` must not contain `..` components: {path}; use an absolute path if the zone \
         directory is outside the working directory"
    )]
    DirectoryTraversal { field: &'static str, path: String },

    /// The configured UDP socket count is larger than the supported safety cap.
    #[cfg(unix)]
    #[error(
        "`udp_socket.sockets` = {value} exceeds the maximum of {max}; values above this can \
         exhaust file descriptors without improving UDP load distribution"
    )]
    UdpSocketCountTooLarge { value: usize, max: usize },
}

fn parse_request_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_secs(u64::deserialize(deserializer)?))
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(5)
}

#[cfg(feature = "__https")]
fn default_http_endpoint() -> String {
    DEFAULT_DNS_QUERY_PATH.to_string()
}

fn default_directory() -> PathBuf {
    PathBuf::from("/var/named") // TODO what about windows (do I care? ;)
}

fn default_port() -> u16 {
    53
}

#[cfg(any(feature = "__tls", feature = "__quic"))]
fn default_tls_port() -> u16 {
    853
}

#[cfg(feature = "__https")]
fn default_https_port() -> u16 {
    443
}
