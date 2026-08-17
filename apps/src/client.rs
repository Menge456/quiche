use crate::args::*;
use crate::common::*;

use std::io::prelude::*;
use std::rc::Rc;
use std::cell::RefCell;

use ring::rand::*;
use quiche::BbrParams;

const MAX_DATAGRAM_SIZE: usize = 1350;

// Bulk write size for the stream-saturation loop below. iperf3 defaults to
// a 128 KiB write size for TCP tests; we mirror that here. This is purely
// an application-layer write chunk size -- quiche/the congestion control
// algorithm still decides how much of it actually goes out per datagram.
const SEND_BUF_SIZE: usize = 128 * 1024;

// How often to print an iperf-style interval throughput report.
const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    Other(String),
}

pub fn connect(
    args: ClientArgs, conn_args: CommonArgs,
    output_sink: impl FnMut(String) + 'static,
) -> Result<(), ClientError> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let _output_sink =
        Rc::new(RefCell::new(output_sink)) as Rc<RefCell<dyn FnMut(_)>>;

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // We'll only connect to the first server provided in URL list.
    let connect_url = &args.urls[0];

    // Resolve server address.
    let peer_addr = if let Some(addr) = &args.connect_to {
        addr.parse().expect("--connect-to is expected to be a string containing an IPv4 or IPv6 address with a port. E.g. 192.0.2.0:443")
    } else {
        *connect_url.socket_addrs(|| None).unwrap().first().unwrap()
    };

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the server address.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    // Create the UDP socket backing the QUIC connection, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let migrate_socket = if args.perform_migration {
        let mut socket =
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(1), mio::Interest::READABLE)
            .unwrap();

        Some(socket)
    } else {
        None
    };

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(args.version).unwrap();

    if let Some(ref trust_origin_ca_pem) = args.trust_origin_ca_pem {
        config
            .load_verify_locations_from_file(trust_origin_ca_pem)
            .map_err(|e| {
                ClientError::Other(format!("error loading origin CA file : {e}"))
            })?;
    } else {
        config.verify_peer(!args.no_verify);
    }

    // Must match the server's ALPN override -- see the comment next to
    // the corresponding set_application_protos() call in server.rs for
    // why conn_args.alpns (h3/hq-interop) isn't used here.
    config.set_application_protos(&[b"raw-bulk-transfer"]).unwrap();
    config.set_initial_rtt(conn_args.initial_rtt);
    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);
    config.set_initial_congestion_window_packets(
        usize::try_from(conn_args.initial_cwnd_packets).unwrap(),
    );

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);
    let cust_bbr = BbrParams {
        startup_cwnd_gain: conn_args.univ_cwnd_gain,
        drain_cwnd_gain: conn_args.univ_cwnd_gain,
        probe_bw_cwnd_gain: conn_args.univ_cwnd_gain,
        probe_bw_up_cwnd_gain: conn_args.univ_cwnd_gain,
        probe_rtt_cwnd_gain: conn_args.univ_cwnd_gain,
        startup_pacing_gain: None,
        full_bw_threshold: None,
        startup_full_bw_rounds: None,
        startup_full_loss_count: None,
        drain_pacing_gain: None,
        enable_reno_coexistence: None,
        enable_overestimate_avoidance: None,
        choose_a0_point_fix: None,
        probe_bw_probe_up_pacing_gain: None,
        probe_bw_probe_down_pacing_gain: None,
        probe_rtt_pacing_gain: None,
        max_probe_up_queue_rounds: None,
        loss_threshold: None,
        use_bytes_delivered_for_inflight_hi: None,
        decrease_startup_pacing_at_end_of_round: None,
        bw_lo_reduction_strategy: None,
        ignore_app_limited_for_no_bandwidth_growth: None,
        initial_pacing_rate_bytes_per_second: None,
        scale_pacing_rate_by_mss: None,
        disable_probe_down_early_exit: None,
        time_sent_set_to_now: None,
        rtt_jump_detector: None,
    };
    config.set_custom_bbr_params(cust_bbr);
    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    // Generate a random source connection ID for the connection.
    let rng = SystemRandom::new();

    let scid = if !cfg!(feature = "fuzzing") {
        let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
        rng.fill(&mut conn_id[..]).unwrap();

        conn_id.to_vec()
    } else {
        [0; quiche::MAX_CONN_ID_LEN].to_vec()
    };

    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(
        connect_url.domain(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{scid:?}");
            let writer = make_qlog_writer(&dir, "client", &id);

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }
    }

    if let Some(session_file) = &args.session_file {
        if let Ok(session) = std::fs::read(session_file) {
            conn.set_session(&session).ok();
        }
    }

    info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addr,
        socket.local_addr().unwrap(),
        scid,
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!(
                "{} -> {}: send() would block",
                socket.local_addr().unwrap(),
                send_info.to
            );
            continue;
        }

        return Err(ClientError::Other(format!("send() failed: {e:?}")));
    }

    trace!("written {write}");

    let app_data_start = std::time::Instant::now();

    let mut pkt_count = 0;

    let mut scid_sent = false;
    let mut new_path_probed = false;
    let mut migrated = false;

    // Stream ID 2 is the first client-initiated unidirectional stream in QUIC
    let stream_id = 2;

    // Reusable bulk payload. Content doesn't matter for a throughput test,
    // so it's just zero-filled once up front.
    let send_buf = vec![0u8; SEND_BUF_SIZE];

    let mut total_bytes_sent: u64 = 0;
    let mut interval_bytes_sent: u64 = 0;
    let mut last_report = std::time::Instant::now();
    let dur_track = std::time::Instant::now();
    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Handle timeouts.
        if events.is_empty() {
            trace!("timed out");
            conn.on_timeout();
        }

        // Process incoming UDP packets (ACKs, stream control from server).
        for event in &events {
            let socket = match event.token() {
                mio::Token(0) => &socket,
                mio::Token(1) => migrate_socket.as_ref().unwrap(),
                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("{local_addr}: recv() would block");
                            break 'read;
                        }
                        return Err(ClientError::Other(format!(
                            "{local_addr}: recv() failed: {e:?}"
                        )));
                    },
                };

                trace!("got {len} bytes from {from} to {local_addr}");

                if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                    let path = format!("{target_path}/{pkt_count}.pkt");
                    if let Ok(f) = std::fs::File::create(path) {
                        let mut f = std::io::BufWriter::new(f);
                        f.write_all(&buf[..len]).ok();
                    }
                }

                pkt_count += 1;

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("{local_addr}: recv failed: {e:?}");
                        continue 'read;
                    },
                };

                trace!("{local_addr}: processed {read} bytes");

                // Drain any data the server sent back. quiche buffers
                // received stream bytes internally, so if nothing ever
                // calls stream_recv(), flow control will eventually stall
                // the stream once the receive buffer fills up.
                for stream_id in conn.readable() {
                    let mut stream_buf = [0; 65535];

                    while let Ok((read, fin)) =
                        conn.stream_recv(stream_id, &mut stream_buf)
                    {
                        trace!(
                            "received {} bytes on stream {} (fin={})",
                            read, stream_id, fin
                        );

                        if fin {
                            break;
                        }
                    }
                }
            }
        }

        trace!("done reading");

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            info!(
                "sent {:.2} MBytes in {:.2} sec ({:.2} Mbits/sec)",
                total_bytes_sent as f64 / 1_048_576.0,
                app_data_start.elapsed().as_secs_f64(),
                (total_bytes_sent as f64 * 8.0) /
                    app_data_start.elapsed().as_secs_f64() /
                    1_000_000.0
            );

            if !conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );
                return Err(ClientError::HandshakeFail);
            }

            if let Some(session_file) = &args.session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, session).ok();
                }
            }

            break;
        }

        // Saturate the stream with data, iperf-style: rather than sending
        // one small message and stopping, keep calling stream_send() with
        // a large buffer so quiche's own congestion control (whichever
        // algorithm was chosen via --cc-algorithm / the custom BBR params
        // above, unchanged here) is what paces bytes onto the wire -- the
        // same way iperf just keeps write()-ing into a TCP socket and lets
        // the OS's TCP stack decide the actual send rate.
        //
        // Importantly, this is capped to roughly one send_quantum() worth
        // of data per pass through the outer loop, rather than looping
        // until Error::Done unconditionally. quiche will happily accept
        // many megabytes into a stream's send buffer if the peer has
        // granted a large flow-control window, and buffering all of it in
        // one go starves the rest of the loop -- reading incoming ACKs,
        // flushing packets onto the socket, printing reports -- which is
        // what made the client look like it "stopped" after one
        // iteration. Buffering more than a burst's worth doesn't help
        // throughput anyway, since quiche can only put send_quantum()
        // bytes on the wire per round regardless.
        if conn.is_established() || conn.is_in_early_data() {
            let send_budget = conn.send_quantum().max(send_buf.len());
            let mut sent_this_round = 0;

            while sent_this_round < send_budget {
                let chunk_len =
                    send_buf.len().min(send_budget - sent_this_round);

                match conn.stream_send(stream_id, &send_buf[..chunk_len], false)
                {
                    Ok(written) => {
                        total_bytes_sent += written as u64;
                        interval_bytes_sent += written as u64;
                        sent_this_round += written;

                        // A short write means the send/flow-control window
                        // is momentarily exhausted; stop for now and let
                        // the outer loop flush what's already queued.
                        if written < chunk_len {
                            break;
                        }
                    },

                    Err(quiche::Error::Done) => {
                        // No capacity available right now (stream/
                        // connection flow control, or congestion window
                        // is full). Back off until the next iteration.
                        break;
                    },

                    Err(e) => {
                        error!("Stream send failed: {:?}", e);
                        break;
                    },
                }
            }
        }

        // Print an iperf-style interval throughput report roughly once a
        // second: "[start-end sec]  N MBytes  N Mbits/sec".
        let now = std::time::Instant::now();
        if now.duration_since(last_report) >= REPORT_INTERVAL {
            let elapsed = now.duration_since(last_report).as_secs_f64();
            let mbits_per_sec =
                (interval_bytes_sent as f64 * 8.0) / elapsed / 1_000_000.0;

            info!(
                "[{:>6.2}-{:>6.2} sec]  {:>8.2} MBytes  {:>8.2} Mbits/sec",
                now.duration_since(app_data_start).as_secs_f64() - elapsed,
                now.duration_since(app_data_start).as_secs_f64(),
                interval_bytes_sent as f64 / 1_048_576.0,
                mbits_per_sec
            );

            interval_bytes_sent = 0;
            last_report = now;
        }

        // Handle path events.
        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(..) => unreachable!(),

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!("Path ({local_addr}, {peer_addr}) is now validated");
                    conn.migrate(local_addr, peer_addr).unwrap();
                    migrated = true;
                },

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!("Path ({local_addr}, {peer_addr}) failed validation");
                },

                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!(
                        "Path ({local_addr}, {peer_addr}) is now closed and unusable"
                    );
                },

                quiche::PathEvent::ReusedSourceConnectionId(
                    cid_seq,
                    old,
                    new,
                ) => {
                    info!(
                        "Peer reused cid seq {cid_seq} (initially {old:?}) on {new:?}"
                    );
                },

                quiche::PathEvent::PeerMigrated(..) => unreachable!(),
            }
        }

        while let Some(retired_scid) = conn.retired_scid_next() {
            info!("Retiring source CID {retired_scid:?}");
        }

        while conn.scids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);

            if conn.new_scid(&scid, reset_token, false).is_err() {
                break;
            }

            scid_sent = true;
        }

        if args.perform_migration &&
            !new_path_probed &&
            scid_sent &&
            conn.available_dcids() > 0
        {
            let additional_local_addr =
                migrate_socket.as_ref().unwrap().local_addr().unwrap();
            conn.probe_path(additional_local_addr, peer_addr).unwrap();

            new_path_probed = true;
        }

        // Flush enqueued QUIC packets to network sockets
        let mut sockets = vec![&socket];
        if let Some(migrate_socket) = migrate_socket.as_ref() {
            sockets.push(migrate_socket);
        }

        for socket in sockets {
            let local_addr = socket.local_addr().unwrap();

            for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) = match conn.send_on_path(
                        &mut out,
                        Some(local_addr),
                        Some(peer_addr),
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("{local_addr} -> {peer_addr}: done writing");
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{local_addr} -> {peer_addr}: send failed: {e:?}"
                            );

                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!(
                                "{} -> {}: send() would block",
                                local_addr,
                                send_info.to
                            );
                            break;
                        }

                        return Err(ClientError::Other(format!(
                            "{} -> {}: send() failed: {:?}",
                            local_addr, send_info.to, e
                        )));
                    }

                    trace!(
                        "written {write} bytes from {local_addr} to {}",
                        send_info.to
                    );
                }
            }
        }

        let _ = match conn_args.run_timeout{
            Some(dur) => {
                if dur_track.elapsed() >= dur{
                    conn.close(true, 0x1, b"timeout reached").ok();
                }; ()},
            None =>(),
        };

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            info!(
                "sent {:.2} MBytes in {:.2} sec ({:.2} Mbits/sec)",
                total_bytes_sent as f64 / 1_048_576.0,
                app_data_start.elapsed().as_secs_f64(),
                (total_bytes_sent as f64 * 8.0) /
                    app_data_start.elapsed().as_secs_f64() /
                    1_000_000.0
            );

            if !conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );
                return Err(ClientError::HandshakeFail);
            }

            if let Some(session_file) = &args.session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, session).ok();
                }
            }

            break;
        }
    }

    Ok(())
}