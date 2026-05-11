#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use std::sync::Arc;
use std::time::Duration;
use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
#[cfg(feature = "metrics")]
use metrics_process::Collector;
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use rustls::KeyLogFile;
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
use rustls::server::ResolvesServerCert;
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(any(feature = "metrics", all(unix, feature = "systemd")))]
use tokio::time::sleep;
#[cfg(any(
    feature = "__tls",
    feature = "__https",
    feature = "__quic",
    all(unix, feature = "systemd"),
))]
use tracing::{error, info, warn};

use hickory_server::proto::ProtoError;
use hickory_server::proto::rr::rdata::opt::NSIDPayload;
#[cfg(feature = "__tls")]
use hickory_server::server::default_tls_server_config;
use hickory_server::{server::Server, zone_handler::Catalog};

mod config;
use config::{Config, TcpSocketConfig, UdpSocketConfig};

#[cfg(feature = "__dnssec")]
pub mod dnssec;

#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "metrics")]
use crate::metrics::ConfigMetrics;

#[cfg(feature = "prometheus-metrics")]
mod prometheus_server;
#[cfg(feature = "prometheus-metrics")]
use prometheus_server::PrometheusServer;

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(name = "Hickory DNS named server", version, about)]
pub struct DnsServer {
    /// Test validation of configuration files
    #[clap(long = "validate")]
    validate: bool,

    /// Number of runtime workers, defaults to the number of CPU cores
    #[clap(long = "workers")]
    pub workers: Option<usize>,

    /// Disable INFO messages, WARN and ERROR will remain
    #[clap(short = 'q', long = "quiet", conflicts_with = "debug")]
    pub quiet: bool,

    /// Turn on `DEBUG` messages (default is only `INFO`)
    #[clap(short = 'd', long = "debug", conflicts_with = "quiet")]
    pub debug: bool,

    /// Path to configuration file of named server
    #[clap(
        short = 'c',
        long = "config",
        default_value = "/etc/named.toml",
        value_name = "NAME",
        value_hint=clap::ValueHint::FilePath,
    )]
    config: PathBuf,

    /// Path to the root directory for all zone files,
    /// see also config toml
    #[clap(short = 'z', long = "zonedir", value_name = "DIR", value_hint=clap::ValueHint::DirPath)]
    zonedir: Option<PathBuf>,

    /// Listening port for DNS queries,
    /// overrides any value in config file
    #[clap(short = 'p', long = "port", value_name = "PORT")]
    port: Option<u16>,

    /// Listening port for DNS over TLS queries,
    /// overrides any value in config file
    #[cfg(feature = "__tls")]
    #[clap(long = "tls-port", value_name = "TLS-PORT")]
    tls_port: Option<u16>,

    /// Listening port for DNS over HTTPS queries,
    /// overrides any value in config file
    #[cfg(feature = "__https")]
    #[clap(long = "https-port", value_name = "HTTPS-PORT")]
    https_port: Option<u16>,

    /// Listening port for DNS over QUIC queries,
    /// overrides any value in config file
    #[cfg(feature = "__quic")]
    #[clap(long = "quic-port", value_name = "QUIC-PORT")]
    quic_port: Option<u16>,

    /// Listening socket for Prometheus metrics,
    /// for remote access configure socket as needed (e.g. 0.0.0.0:9000)
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(
        long = "prometheus-listen-address",
        value_name = "PROMETHEUS-LISTEN-ADDRESS"
    )]
    prometheus_listen_addr: Option<SocketAddr>,

    /// Disable TCP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-tcp")]
    disable_tcp: bool,

    /// Disable UDP protocol,
    /// overrides any value in config file
    #[clap(long = "disable-udp")]
    disable_udp: bool,

    /// Disable TLS protocol,
    /// overrides any value in config file
    #[cfg(feature = "__tls")]
    #[clap(long = "disable-tls", conflicts_with = "tls_port")]
    disable_tls: bool,

    /// Disable HTTPS protocol,
    /// overrides any value in config file
    #[cfg(feature = "__https")]
    #[clap(long = "disable-https", conflicts_with = "https_port")]
    disable_https: bool,

    /// Disable QUIC protocol,
    /// overrides any value in config file
    #[cfg(feature = "__quic")]
    #[clap(long = "disable-quic", conflicts_with = "quic_port")]
    disable_quic: bool,

    /// Disable Prometheus metrics,
    /// overrides any value in config file
    #[cfg(feature = "prometheus-metrics")]
    #[clap(long = "disable-prometheus", conflicts_with = "prometheus_listen_addr")]
    disable_prometheus: bool,

    /// Name server identifier (NSID) payload for EDNS responses.
    /// Use `0x` prefix for hex-encoded data. Mutually exclusive with --nsid-hostname
    #[clap(long = "nsid", value_name = "NSID", conflicts_with = "nsid_hostname", value_parser = parse_nsid_payload)]
    nsid: Option<NSIDPayload>,

    /// Use the system hostname as the name server identifier (NSID) payload
    /// for EDNS responses.
    /// Mutually exclusive with --nsid
    #[clap(long = "nsid-hostname", conflicts_with = "nsid")]
    nsid_hostname: bool,
}

impl DnsServer {
    pub async fn run(self) -> Result<(), String> {
        let Self {
            validate,
            workers: _, // Used in `main()`
            quiet: _,   // Used in `main()`
            debug: _,   // Used in `main()`
            config,
            zonedir,
            port,
            #[cfg(feature = "__tls")]
            tls_port,
            #[cfg(feature = "__https")]
            https_port,
            #[cfg(feature = "__quic")]
            quic_port,
            #[cfg(feature = "prometheus-metrics")]
            prometheus_listen_addr,
            disable_tcp,
            disable_udp,
            #[cfg(feature = "__tls")]
            disable_tls,
            #[cfg(feature = "__https")]
            disable_https,
            #[cfg(feature = "__quic")]
            disable_quic,
            #[cfg(feature = "prometheus-metrics")]
            disable_prometheus,
            nsid,
            nsid_hostname,
        } = self;

        let config_path = Path::new(&config);
        info!("loading configuration from: {config_path:?}");
        let config = Config::read_config(config_path)
            .map_err(|err| format!("failed to read config file from {config_path:?}: {err}"))?;
        if let Some(zonedir) = &zonedir {
            Config::check_directory_path(zonedir, "zonedir")
                .map_err(|err| format!("invalid zonedir override: {err}"))?;
        }

        #[cfg(feature = "prometheus-metrics")]
        let disable_prometheus = disable_prometheus | config.disable_prometheus;
        let disable_udp = disable_udp | config.disable_udp;
        let disable_tcp = disable_tcp | config.disable_tcp;
        #[cfg(feature = "__tls")]
        let disable_tls = disable_tls | config.disable_tls;
        #[cfg(feature = "__https")]
        let disable_https = disable_https | config.disable_https;
        #[cfg(feature = "__quic")]
        let disable_quic = disable_quic | config.disable_quic;

        #[cfg(feature = "prometheus-metrics")]
        let prometheus_server_opt = if !disable_prometheus {
            let socket_addr = prometheus_listen_addr.unwrap_or_else(|| {
                config
                    .prometheus_listen_addr
                    .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000))
            });
            let listener = build_tcp_listener(
                socket_addr.ip(),
                socket_addr.port(),
                TcpSocketConfig::default(),
            )
            .map_err(|err| {
                format!("failed to bind to Prometheus TCP socket address {socket_addr:?}: {err}")
            })?;
            let local_addr = listener
                .local_addr()
                .map_err(|err| format!("failed to look up local address: {err}"))?;

            // Set up Prometheus HTTP server.
            let server = PrometheusServer::new(listener)?;
            info!("listening for Prometheus metrics on {local_addr:?}");
            Some(server)
        } else {
            info!("Prometheus metrics are disabled");
            None
        };

        #[cfg(feature = "metrics")]
        let (process_metrics_collector, config_metrics) = {
            // setup process metrics (cpu, memory, ...) collection
            let collector = Collector::default();
            collector.describe(); // add metric descriptions

            let process_metrics_collector = tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(1)).await;
                    collector.collect();
                }
            });

            // metrics need to be created after the recorder is registered
            // calling increment() after registration is not sufficient
            let config_metrics = ConfigMetrics::new(&config);
            (process_metrics_collector, config_metrics)
        };

        let Config {
            listen_addrs_ipv4,
            listen_addrs_ipv6,
            listen_port,
            #[cfg(feature = "__tls")]
            tls_listen_port,
            #[cfg(feature = "__https")]
            https_listen_port,
            #[cfg(feature = "__quic")]
            quic_listen_port,
            #[cfg(feature = "prometheus-metrics")]
                prometheus_listen_addr: _,
            disable_tcp: _,
            disable_udp: _,
            #[cfg(feature = "__tls")]
                disable_tls: _,
            #[cfg(feature = "__https")]
                disable_https: _,
            #[cfg(feature = "__quic")]
                disable_quic: _,
            #[cfg(feature = "prometheus-metrics")]
                disable_prometheus: _,
            tcp_request_timeout,
            #[cfg(feature = "__tls")]
            ssl_keylog_enabled,
            directory,
            user,
            group,
            zones,
            #[cfg(feature = "__tls")]
            tls_cert,
            #[cfg(feature = "__https")]
            http_endpoint,
            deny_networks,
            allow_networks,
            udp_socket: udp_socket_config,
            tcp_socket: tcp_socket_config,
        } = config;

        #[cfg(unix)]
        let mut signal = signal(SignalKind::terminate())
            .map_err(|e| format!("failed to register signal handler: {e}"))?;

        let mut catalog = Catalog::new();
        catalog.set_nsid(nsid);

        if nsid_hostname {
            let hostname =
                hostname::get().map_err(|e| format!("failed to get system hostname: {e}"))?;
            let payload = NSIDPayload::new(hostname.into_encoded_bytes())
                .map_err(|e| format!("invalid NSID payload: {e}"))?;
            catalog.set_nsid(Some(payload));
        }

        // configure our server based on the config_path
        let zone_dir = zonedir.unwrap_or(directory);
        for zone in zones {
            let zone_name = zone
                .zone()
                .map_err(|err| format!("failed to read zone name from {config_path:?}: {err}"))?;

            #[cfg(feature = "metrics")]
            config_metrics.increment_zone_metrics(&zone);

            match zone.load_with_mode(&zone_dir, validate).await {
                Ok(handlers) => catalog.upsert(zone_name.into(), handlers),
                Err(err) => return Err(format!("could not load zone {zone_name}: {err}")),
            }
        }

        if validate {
            info!("configuration files are validated");
            return Ok(());
        }

        // now, run the server, based on the config
        #[cfg_attr(not(feature = "__tls"), allow(unused_mut))]
        let mut server = Server::with_access(catalog, deny_networks, allow_networks);

        let mut listen_addrs = listen_addrs_ipv4
            .into_iter()
            .map(IpAddr::V4)
            .chain(listen_addrs_ipv6.into_iter().map(IpAddr::V6))
            .collect::<Vec<_>>();

        if listen_addrs.is_empty() {
            listen_addrs.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            listen_addrs.push(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        }

        let mut setup = ServerSetup {
            listen_addrs,
            server: &mut server,
            tcp_request_timeout,
            #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
            cert_resolver: tls_cert
                .as_ref()
                .map(|config| {
                    config.load(&zone_dir).map_err(|err| {
                        format!(
                            "failed to load TLS certificate from {:?}: {err}",
                            config.path
                        )
                    })
                })
                .transpose()?,
            #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
            ssl_keylog_enabled,
            udp_socket_config,
            tcp_socket_config,
        };

        let listen_port = port.unwrap_or(listen_port);
        match disable_udp {
            true => info!("UDP protocol is disabled"),
            false => setup.udp(listen_port)?,
        }

        match disable_tcp {
            true => info!("TCP protocol is disabled"),
            false => setup.tcp(listen_port)?,
        }

        #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
        if setup.cert_resolver.is_none() {
            match missing_tls_cert_verdict(
                #[cfg(feature = "__tls")]
                disable_tls,
                #[cfg(feature = "__https")]
                disable_https,
                #[cfg(feature = "__quic")]
                disable_quic,
            ) {
                MissingTlsCertVerdict::ListenerSilentlySkipped => {
                    warn!(
                        "TLS-family transports (DoT/DoH/DoQ) are compiled in and not all disabled, \
                         but no [tls_cert] is configured — those listeners will NOT start. \
                         Either set [tls_cert] or set disable_tls/disable_https/disable_quic = true \
                         to silence this warning."
                    );
                }
                MissingTlsCertVerdict::AllTlsDisabledByConfig => {
                    info!("TLS related protocols (TLS, HTTPS and QUIC) are disabled");
                }
            }
        }

        #[cfg(feature = "__tls")]
        match disable_tls {
            true => info!("TLS protocol is disabled"),
            false => setup.tls(tls_port.unwrap_or(tls_listen_port))?,
        }

        #[cfg(feature = "__https")]
        match disable_https {
            true => info!("HTTPS protocol is disabled"),
            false => setup.https(
                https_port.unwrap_or(https_listen_port),
                &http_endpoint,
                tls_cert
                    .as_ref()
                    .and_then(|config| config.endpoint_name.as_deref()),
            )?,
        }

        #[cfg(feature = "__quic")]
        match disable_quic {
            true => info!("QUIC protocol is disabled"),
            false => setup.quic(quic_port.unwrap_or(quic_listen_port))?,
        }

        // Drop privileges on Unix systems if running as root.
        #[cfg(target_family = "unix")]
        check_drop_privs(
            user.as_deref().unwrap_or(DEFAULT_USER),
            group.as_deref().unwrap_or(DEFAULT_GROUP),
        )?;
        #[cfg(not(target_family = "unix"))]
        if user.is_some() || group.is_some() {
            return Err("dropping privileges is only supported on Unix systems".to_string());
        }

        #[cfg(unix)]
        {
            let token = server.shutdown_token().clone();
            tokio::spawn(async move {
                signal.recv().await;
                token.cancel();
            });
        }

        // config complete, starting!
        banner();

        // TODO: how to do threads? should we do a bunch of listener threads and then query threads?
        // Ideally the processing would be n-threads for receiving, which hand off to m-threads for
        //  request handling. It would generally be the case that n <= m.
        info!("server starting up, awaiting connections...");

        #[cfg(all(unix, feature = "systemd"))]
        sd_notify::notify(&[sd_notify::NotifyState::Ready])
            .map_err(|e| format!("sd_notify READY=1 failed: {e}"))?;

        #[cfg(all(unix, feature = "systemd"))]
        if let Some(timeout) = sd_notify::watchdog_enabled() {
            let interval = timeout / 2;
            let token = server.shutdown_token().clone();
            tokio::spawn(async move {
                loop {
                    sleep(interval).await;
                    if token.is_cancelled() {
                        break;
                    }
                    if let Err(error) = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]) {
                        warn!(%error, "systemd watchdog ping failed");
                    }
                }
            });
            info!(?interval, "systemd watchdog enabled");
        }

        match server.block_until_done().await {
            Ok(()) => {
                // we're exiting for some reason...
                #[cfg(all(unix, feature = "systemd"))]
                sd_notify::notify(&[sd_notify::NotifyState::Stopping]).ok();
                info!("Hickory DNS {} stopping", env!("CARGO_PKG_VERSION"));
            }
            Err(e) => {
                let error_msg = format!(
                    "Hickory DNS {} has encountered an error: {}",
                    env!("CARGO_PKG_VERSION"),
                    e
                );

                error!("{}", error_msg);
                panic!("{}", error_msg);
            }
        };

        // Shut down the Prometheus metrics server after the DNS server has gracefully shut down.
        #[cfg(feature = "prometheus-metrics")]
        if let Some(server) = prometheus_server_opt {
            server.stop().await;
        }

        #[cfg(feature = "metrics")]
        process_metrics_collector.abort();

        Ok(())
    }
}

struct ServerSetup<'a> {
    listen_addrs: Vec<IpAddr>,
    server: &'a mut Server<Catalog>,
    tcp_request_timeout: Duration,
    #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
    cert_resolver: Option<Arc<dyn ResolvesServerCert>>,
    #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
    ssl_keylog_enabled: bool,
    udp_socket_config: UdpSocketConfig,
    tcp_socket_config: TcpSocketConfig,
}

impl ServerSetup<'_> {
    fn udp(&mut self, port: u16) -> Result<(), String> {
        #[cfg(unix)]
        let num_sockets = self.udp_socket_config.sockets.unwrap_or(1);
        #[cfg(not(unix))]
        let num_sockets = 1_usize;
        for addr in &self.listen_addrs {
            info!("binding {num_sockets} UDP socket(s) to {addr:?}:{port}");

            // Bind the first socket up-front so we can log the local address. This is helpful
            // when binding :0 and allowing the OS to choose the listen port.
            let first_socket = build_udp_socket(*addr, port, self.udp_socket_config)
                .map_err(|err| format!("failed to bind to UDP socket address {addr:?}: {err}"))?;
            let bound_addr = first_socket
                .local_addr()
                .map_err(|err| format!("failed to lookup local address: {err}"))?;
            self.server.register_socket(first_socket);

            // Afterward, bind any additional sockets.
            for _ in 1..num_sockets {
                self.server.register_socket(
                    build_udp_socket(*addr, port, self.udp_socket_config).map_err(|err| {
                        format!("failed to bind to UDP socket address {addr:?}: {err}")
                    })?,
                );
            }

            info!("listening for UDP on {bound_addr:?}");
        }

        Ok(())
    }

    fn tcp(&mut self, port: u16) -> Result<(), String> {
        for addr in &self.listen_addrs {
            info!("binding TCP to {addr:?}");

            let tcp_listener = build_tcp_listener(*addr, port, self.tcp_socket_config)
                .map_err(|err| format!("failed to bind to TCP socket address {addr:?}: {err}"))?;

            info!(
                "listening for TCP on {:?}",
                tcp_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            self.server.register_listener(
                tcp_listener,
                self.tcp_request_timeout,
                self.tcp_socket_config.response_buffer_size,
            );
        }

        Ok(())
    }

    #[cfg(feature = "__tls")]
    fn tls(&mut self, port: u16) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("binding TLS to {addr:?}");

            let tls_listener = build_tcp_listener(*addr, port, self.tcp_socket_config)
                .map_err(|err| format!("failed to bind to TLS socket address {addr:?}: {err}"))?;

            info!(
                "listening for TLS on {:?}",
                tls_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"dot", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                tls_config.key_log = keylog_for("DoT");
            }

            self.server
                .register_tls_listener_with_tls_config(
                    tls_listener,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                )
                .map_err(|err| format!("failed to register TLS listener: {err}"))?;
        }
        Ok(())
    }

    #[cfg(feature = "__https")]
    fn https(
        &mut self,
        port: u16,
        http_endpoint: &str,
        dns_hostname: Option<&str>,
    ) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("binding HTTPS to {addr:?}");

            let https_listener = build_tcp_listener(*addr, port, self.tcp_socket_config)
                .map_err(|err| format!("failed to bind to HTTPS socket address {addr:?}: {err}"))?;

            info!(
                "listening for HTTPS on {:?}",
                https_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"h2", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                tls_config.key_log = keylog_for("DoH");
            }

            self.server
                .register_https_listener_with_tls_config(
                    https_listener,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                    dns_hostname.map(|s| s.to_owned()),
                    http_endpoint.to_owned(),
                )
                .map_err(|err| format!("failed to register HTTPS listener: {err}"))?;
        }

        Ok(())
    }

    #[cfg(feature = "__quic")]
    fn quic(&mut self, port: u16) -> Result<(), String> {
        let Some(cert_resolver) = &self.cert_resolver else {
            return Ok(());
        };

        for addr in &self.listen_addrs {
            info!("Binding QUIC to {addr:?}");

            let quic_listener = build_udp_socket(*addr, port, self.udp_socket_config)
                .map_err(|err| format!("failed to bind to QUIC socket address {addr:?}: {err}"))?;

            info!(
                "listening for QUIC on {:?}",
                quic_listener
                    .local_addr()
                    .map_err(|err| format!("failed to lookup local address: {err}"))?
            );

            let mut tls_config = default_tls_server_config(b"doq", cert_resolver.clone())
                .map_err(|err| format!("failed to build default TLS config: {err}"))?;
            if self.ssl_keylog_enabled {
                tls_config.key_log = keylog_for("DoQ");
            }

            self.server
                .register_quic_listener_and_tls_config(
                    quic_listener,
                    self.tcp_request_timeout,
                    Arc::new(tls_config),
                )
                .map_err(|err| format!("failed to register QUIC listener: {err}"))?;
        }
        Ok(())
    }
}

/// Verdict returned by [`missing_tls_cert_verdict`] when no `[tls_cert]` is
/// configured but the binary supports TLS-family transports.
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
#[derive(Debug, PartialEq, Eq)]
enum MissingTlsCertVerdict {
    /// At least one TLS-family transport is still enabled in config; the
    /// listener will silently not start. Operator should see a warning.
    ListenerSilentlySkipped,
    /// Every TLS-family transport is disabled in config. Skipping the
    /// listener is exactly what the operator asked for; an info log suffices.
    AllTlsDisabledByConfig,
}

/// Decide whether to warn about a missing `[tls_cert]` block.
///
/// Pure function over the only inputs that matter so it can be unit-tested
/// without binding ports or starting the server.
#[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
fn missing_tls_cert_verdict(
    #[cfg(feature = "__tls")] disable_tls: bool,
    #[cfg(feature = "__https")] disable_https: bool,
    #[cfg(feature = "__quic")] disable_quic: bool,
) -> MissingTlsCertVerdict {
    let mut any_tls_enabled = false;
    #[cfg(feature = "__tls")]
    {
        any_tls_enabled |= !disable_tls;
    }
    #[cfg(feature = "__https")]
    {
        any_tls_enabled |= !disable_https;
    }
    #[cfg(feature = "__quic")]
    {
        any_tls_enabled |= !disable_quic;
    }
    if any_tls_enabled {
        MissingTlsCertVerdict::ListenerSilentlySkipped
    } else {
        MissingTlsCertVerdict::AllTlsDisabledByConfig
    }
}

/// Construct a `KeyLogFile` while logging exactly which path will receive
/// the TLS session keys. `KeyLogFile::new()` reads `SSLKEYLOGFILE` lazily
/// at construction time; the operator who enabled `ssl_keylog_enabled` in
/// the config should see in the log where keys are being written, including
/// the "no SSLKEYLOGFILE set, key logging silently disabled" case (an easy
/// way to think key-logging is on when it isn't).
#[cfg(feature = "__tls")]
fn keylog_for(transport: &str) -> Arc<KeyLogFile> {
    match std::env::var_os("SSLKEYLOGFILE") {
        Some(path) => {
            warn!(
                "{transport} TLS session key logging is ENABLED, keys will be written to {:?} \
                 — anything with read access to that file can decrypt captured {transport} traffic",
                path
            );
        }
        None => {
            warn!(
                "{transport} ssl_keylog_enabled is set but SSLKEYLOGFILE env var is unset; \
                 no keys will be written"
            );
        }
    }
    Arc::new(KeyLogFile::new())
}

fn banner() {
    #[cfg(feature = "ascii-art")]
    const HICKORY_DNS_LOGO: &str = include_str!("hickory-dns.ascii");

    #[cfg(not(feature = "ascii-art"))]
    const HICKORY_DNS_LOGO: &str = "Hickory DNS";

    info!("");
    for line in HICKORY_DNS_LOGO.lines() {
        info!(" {line}");
    }
    info!("");
}

/// Build a TcpListener for a given IP, port pair; IPv6 listeners will not accept v4 connections
fn build_tcp_listener(
    ip: IpAddr,
    port: u16,
    socket_config: TcpSocketConfig,
) -> Result<TcpListener, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::STREAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    sock.listen(socket_config.listen_backlog)?;

    TcpListener::from_std(sock.into())
}

/// Build a UdpSocket for a given IP, port pair; IPv6 sockets will not accept v4 connections
fn build_udp_socket(
    ip: IpAddr,
    port: u16,
    socket_config: UdpSocketConfig,
) -> Result<UdpSocket, Error> {
    let sock = if ip.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, None)?
    } else {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s
    };

    sock.set_nonblocking(true)?;

    #[cfg(unix)]
    if socket_config.sockets.is_some_and(|count| count > 1) {
        sock.set_reuse_port(true)?;
    }

    if let Some(size) = socket_config.recv_buffer_size {
        sock.set_recv_buffer_size(size)?;
    }
    if let Some(size) = socket_config.send_buffer_size {
        sock.set_send_buffer_size(size)?;
    }
    if socket_config.recv_buffer_size.is_some() || socket_config.send_buffer_size.is_some() {
        let actual_recv = sock.recv_buffer_size().unwrap_or(0);
        let actual_send = sock.send_buffer_size().unwrap_or(0);
        info!(
            "UDP socket buffer sizes: recv={actual_recv} send={actual_send} \
             (requested recv={:?} send={:?})",
            socket_config.recv_buffer_size, socket_config.send_buffer_size,
        );
        if let Some(req) = socket_config.recv_buffer_size {
            if actual_recv < req {
                warn!(
                    "kernel capped UDP recv buffer at {actual_recv}, below the requested {req}; \
                     increase net.core.rmem_max (Linux) or kern.ipc.maxsockbuf (BSD/macOS) \
                     to absorb traffic bursts as configured"
                );
            }
        }
        if let Some(req) = socket_config.send_buffer_size {
            if actual_send < req {
                warn!(
                    "kernel capped UDP send buffer at {actual_send}, below the requested {req}; \
                     increase net.core.wmem_max (Linux) or kern.ipc.maxsockbuf (BSD/macOS)"
                );
            }
        }
    }

    let s_addr = SocketAddr::new(ip, port);
    sock.bind(&s_addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Drop privileges on Unix systems if running as root. Errors that prevent dropping privileges will
/// halt the server.  This must be called after binding to low numbered sockets is complete.
#[cfg(target_family = "unix")]
fn check_drop_privs(user: &str, group: &str) -> Result<(), String> {
    use libc::{getegid, geteuid, getgid, getgrnam, getpwnam, getuid, setgid, setuid};
    use std::ffi::CString;

    // These calls are guaranteed to succeed in a POSIX-conforming environment. In non-conforming
    // environments, implementations may return -1 to indicate a process running without an
    // associated UID/EUID/GID/EGID. In that case, our main block below will not execute as
    // libc typedefs uid_t and gid_t to u32; -1 will be u32::MAX.
    //
    // POSIX reference: IEEE Std 1003.1-1024 getuid, geteuid, getgid, and getegid specifications
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/geteuid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgid.html
    // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getegid.html
    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    if uid == 0 || euid == 0 {
        info!(
            "running as root (uid: {uid} gid: {gid} euid: {euid} egid: {egid})...dropping privileges.",
        );

        let Ok(user_cstring) = CString::new(user) else {
            return Err(format!("unable to create CString for user {user}"));
        };

        let Ok(group_cstring) = CString::new(group) else {
            return Err(format!(
                "unable to create CString for group {group}. Exiting."
            ));
        };

        // These functions must be supplied a NULL-terminated string, which is guaranteed by
        // std::ffi::CString.  Upon success, they will return a pointer to a struct passwd or
        // struct group, or NULL upon failure. Testing for a NULL return value is mandatory.
        //
        // POSIX reference: IEEE Std 1003.1-1024 getpwnam and getgrnam specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getpwnam.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/getgrnam.html
        let (user_info, group_info) = unsafe {
            (
                getpwnam(user_cstring.as_ptr()),
                getgrnam(group_cstring.as_ptr()),
            )
        };

        if user_info.is_null() {
            return Err(format!("unable to lookup user '{user}'. Exiting."));
        }

        if group_info.is_null() {
            return Err(format!("unable to lookup group '{group}'. Exiting."));
        }

        // These functions must be supplied a gid_t (setgid) and uid_t (setuid), which are
        // supplied by the passwd and group structs returned by getpwnam and getgrnam.
        // The structs are tested to be valid by the calls to is_null() above.
        //
        // The call to setgid must be completed before the call to setuid is made or the
        // process will almost certainly lack the privileges necessary to switch its real gid.
        //
        // POSIX reference: IEEE Std 1003.1-1024 setgid and setuid specifications
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setgid.html
        // https://pubs.opengroup.org/onlinepubs/9799919799/functions/setuid.html
        let (setgid_rc, setuid_rc) =
            unsafe { (setgid((*group_info).gr_gid), setuid((*user_info).pw_uid)) };

        if setgid_rc < 0 {
            return Err("unable to set gid. Exiting.".into());
        }

        if setuid_rc < 0 {
            return Err("unable to set uid. Exiting.".into());
        }
    }

    let (uid, gid, euid, egid) = unsafe { (getuid(), getgid(), geteuid(), getegid()) };

    info!("now running as uid: {uid}, gid: {gid} (euid: {euid}, egid: {egid})",);
    Ok(())
}

fn parse_nsid_payload(raw_payload: &str) -> Result<NSIDPayload, ProtoError> {
    let bytes = if let Some(hex_str) = raw_payload.strip_prefix("0x") {
        hex::decode(hex_str)
            .map_err(|e| ProtoError::from(format!("invalid NSID hex encoding: {e}")))?
    } else {
        raw_payload.as_bytes().to_vec()
    };
    NSIDPayload::new(bytes)
}

#[cfg(target_family = "unix")]
const DEFAULT_USER: &str = "nobody";
#[cfg(target_family = "unix")]
const DEFAULT_GROUP: &str = "nobody";

#[cfg(test)]
mod tests {
    use hickory_proto::rr::rdata::opt::NSIDPayload;

    use super::parse_nsid_payload;

    #[test]
    fn test_hex_nsid_payload() {
        let expected = NSIDPayload::new(vec![0xC0, 0xFF, 0xEE]).unwrap();
        let value = parse_nsid_payload("0xC0FFEE").unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_string_nsid_payload() {
        let string_value = "HickoryDNS";
        let expected = NSIDPayload::new(string_value.as_bytes()).unwrap();
        let value = parse_nsid_payload(string_value).unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_nsid_payload_too_long() {
        let too_large = "x".repeat(u16::MAX as usize + 1);
        let err = parse_nsid_payload(&too_large).unwrap_err();
        assert_eq!(err.to_string(), "NSID EDNS payload too large");
    }

    #[cfg(any(feature = "__tls", feature = "__https", feature = "__quic"))]
    use super::{MissingTlsCertVerdict, missing_tls_cert_verdict};

    /// When at least one TLS-family transport is enabled in config (any
    /// `disable_*` is false), the verdict must be a warning.
    #[cfg(all(feature = "__tls", feature = "__https", feature = "__quic"))]
    #[test]
    fn missing_cert_with_dot_enabled_warns() {
        assert_eq!(
            missing_tls_cert_verdict(false, true, true),
            MissingTlsCertVerdict::ListenerSilentlySkipped,
        );
    }

    #[cfg(all(feature = "__tls", feature = "__https", feature = "__quic"))]
    #[test]
    fn missing_cert_with_doh_enabled_warns() {
        assert_eq!(
            missing_tls_cert_verdict(true, false, true),
            MissingTlsCertVerdict::ListenerSilentlySkipped,
        );
    }

    #[cfg(all(feature = "__tls", feature = "__https", feature = "__quic"))]
    #[test]
    fn missing_cert_with_doq_enabled_warns() {
        assert_eq!(
            missing_tls_cert_verdict(true, true, false),
            MissingTlsCertVerdict::ListenerSilentlySkipped,
        );
    }

    /// All disable_* set → operator opted out of TLS, no warning needed.
    #[cfg(all(feature = "__tls", feature = "__https", feature = "__quic"))]
    #[test]
    fn missing_cert_all_disabled_is_quiet() {
        assert_eq!(
            missing_tls_cert_verdict(true, true, true),
            MissingTlsCertVerdict::AllTlsDisabledByConfig,
        );
    }
}
