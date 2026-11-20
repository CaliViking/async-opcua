//! A refused CreateSession or ActivateSession writes no log line of its own at
//! INFO or above. The server reports refusals as counts per service and status
//! code, in at most one warning per minute.
//!
//! This is its own test binary, so the capturing logger it installs sees only
//! the server it starts here. The server runs on a runtime whose threads carry
//! one name, and only records written on those threads are kept, which leaves
//! the client's own lines out.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use opcua::{
    client::{ClientBuilder, IdentityToken, Session},
    core::{RequestMessage, ResponseMessage},
    crypto::SecurityPolicy,
    server::{ServerBuilder, ANONYMOUS_USER_TOKEN_ID},
    types::{
        ActivateSessionRequest, CloseSessionRequest, CreateSessionRequest, DateTime,
        ExtensionObject, MessageSecurityMode, NodeId, ReadValueId, RequestHeader, StatusCode,
        UAString,
    },
};

/// The name every thread of the server's runtime carries.
const SERVER_THREAD: &str = "refusal-server";
/// The interval the server reports refusals at.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);
/// The bound on any one wait for the server, which only a hang reaches.
const LIVENESS: Duration = Duration::from_secs(60);

struct Captured {
    level: log::Level,
    message: String,
}

struct ServerLogger {
    records: Mutex<Vec<Captured>>,
}

impl log::Log for ServerLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) || std::thread::current().name() != Some(SERVER_THREAD)
        {
            return;
        }
        self.records.lock().unwrap().push(Captured {
            level: record.level(),
            message: record.args().to_string(),
        });
    }

    fn flush(&self) {}
}

impl ServerLogger {
    fn install() -> &'static ServerLogger {
        static LOGGER: OnceLock<&'static ServerLogger> = OnceLock::new();
        LOGGER.get_or_init(|| {
            let logger: &'static ServerLogger = Box::leak(Box::new(ServerLogger {
                records: Mutex::new(Vec::new()),
            }));
            log::set_logger(logger).expect("this binary installs exactly one logger");
            log::set_max_level(log::LevelFilter::Debug);
            logger
        })
    }

    /// A position in the record list, from which [`Self::since`] reads.
    fn mark(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// The level and text of every record written since `mark`.
    fn since(&self, mark: usize) -> Vec<(log::Level, String)> {
        self.records.lock().unwrap()[mark..]
            .iter()
            .map(|r| (r.level, r.message.clone()))
            .collect()
    }
}

fn at_or_above(records: &[(log::Level, String)], level: log::Level) -> Vec<&(log::Level, String)> {
    records.iter().filter(|(l, _)| *l <= level).collect()
}

/// Assert that `records` hold exactly one line at INFO or above, a warning
/// naming exactly `counts`.
fn assert_one_report(records: &[(log::Level, String)], counts: &str) {
    let lines = at_or_above(records, log::Level::Info);
    assert_eq!(lines.len(), 1, "expected one report line, got {lines:?}");
    let (level, message) = lines[0];
    assert_eq!(*level, log::Level::Warn, "{message}");
    assert!(
        message.ends_with(&format!(": {counts}")),
        "the report must name exactly {counts}: {message}"
    );
}

fn request_header(session: &Session, authentication_token: &NodeId) -> RequestHeader {
    RequestHeader::new(
        authentication_token,
        &DateTime::now(),
        session.request_handle(),
    )
}

async fn send(session: &Session, request: impl Into<RequestMessage>) -> ResponseMessage {
    session
        .channel()
        .send(request, LIVENESS)
        .await
        .expect("the server answers the request")
}

fn fault_status(response: ResponseMessage) -> StatusCode {
    match response {
        ResponseMessage::ServiceFault(fault) => fault.response_header.service_result,
        other => panic!("expected a service fault, got {}", other.type_name()),
    }
}

/// Send a CreateSession with a null endpoint url, which the server refuses.
async fn refuse_create_session(session: &Session) {
    let request = CreateSessionRequest {
        request_header: request_header(session, &NodeId::null()),
        endpoint_url: UAString::null(),
        requested_session_timeout: 60_000.0,
        ..Default::default()
    };
    assert_eq!(
        fault_status(send(session, request).await),
        StatusCode::BadTcpEndpointUrlInvalid
    );
}

/// Create a session on `url`, returning its authentication token. The server
/// accepts this request.
async fn create_session(session: &Session, url: &str) -> NodeId {
    let request = CreateSessionRequest {
        request_header: request_header(session, &NodeId::null()),
        endpoint_url: url.into(),
        requested_session_timeout: 60_000.0,
        ..Default::default()
    };
    match send(session, request).await {
        ResponseMessage::CreateSession(response) => response.authentication_token,
        other => panic!(
            "expected a CreateSession response, got {}",
            other.type_name()
        ),
    }
}

/// Activate the session `token` names with an identity token of a type no
/// identity token has, which the server refuses.
async fn refuse_activate_session(session: &Session, token: &NodeId) {
    let request = ActivateSessionRequest {
        request_header: request_header(session, token),
        user_identity_token: ExtensionObject::from_message(ReadValueId::default()),
        ..Default::default()
    };
    assert_eq!(
        fault_status(send(session, request).await),
        StatusCode::BadIdentityTokenInvalid
    );
}

/// Close the session `token` names, so it does not expire while a test waits.
async fn close_session(session: &Session, token: &NodeId) {
    let request = CloseSessionRequest {
        request_header: request_header(session, token),
        delete_subscriptions: true,
    };
    match send(session, request).await {
        ResponseMessage::CloseSession(_) => {}
        other => panic!(
            "expected a CloseSession response, got {}",
            other.type_name()
        ),
    }
}

#[test]
fn refused_session_establishment_is_reported_as_aggregated_counts() {
    let logger = ServerLogger::install();
    let pki = tempdir::TempDir::new("session-refusals").unwrap();

    let server_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(SERVER_THREAD)
        .enable_all()
        .build()
        .unwrap();
    let (url, handle) = server_rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (server, handle) = ServerBuilder::new()
            .application_name("session_refusals")
            .application_uri("urn:session_refusals")
            .product_uri("urn:session_refusals")
            .create_sample_keypair(true)
            .pki_dir(pki.path().join("server"))
            .host("127.0.0.1")
            .port(port)
            .discovery_urls(vec![format!("opc.tcp://127.0.0.1:{port}/")])
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
                ),
            )
            .build()
            .unwrap();
        tokio::spawn(server.run_with(listener));
        (format!("opc.tcp://127.0.0.1:{port}/"), handle)
    });

    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("refusal-client")
        .enable_all()
        .build()
        .unwrap();
    client_rt.block_on(async {
        let mut client = ClientBuilder::new()
            .application_name("session_refusals_client")
            .application_uri("urn:session_refusals_client")
            .pki_dir(pki.path().join("client"))
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_limit(0)
            .client()
            .unwrap();
        let (session, event_loop): (Arc<Session>, _) = client
            .connect_to_matching_endpoint(
                (
                    url.as_str(),
                    SecurityPolicy::None.to_str(),
                    MessageSecurityMode::None,
                ),
                IdentityToken::Anonymous,
            )
            .await
            .unwrap();
        let _event_loop = event_loop.spawn();
        assert!(
            tokio::time::timeout(LIVENESS, session.wait_for_connection())
                .await
                .expect("the client connects within the liveness bound")
        );

        // The first refusal reports at once, and the refusal's cause is at DEBUG.
        let mark = logger.mark();
        refuse_create_session(&session).await;
        let records = logger.since(mark);
        assert_one_report(&records, "CreateSession BadTcpEndpointUrlInvalid=1");
        assert!(
            records
                .iter()
                .any(|(level, message)| *level == log::Level::Debug
                    && message.contains("null endpoint url")),
            "the refusal's cause must be at DEBUG: {records:?}",
            records = records.iter().map(|(_, m)| m).collect::<Vec<_>>()
        );

        // Refusals within the interval are counted and write no line.
        let token = create_session(&session, &url).await;
        let mark = logger.mark();
        refuse_activate_session(&session, &token).await;
        refuse_create_session(&session).await;
        let records = logger.since(mark);
        let lines = at_or_above(&records, log::Level::Info);
        assert!(lines.is_empty(), "no line within the interval: {lines:?}");
        close_session(&session, &token).await;

        // A refusal after the interval reports every count since the previous report.
        tokio::time::sleep(REPORT_INTERVAL + Duration::from_secs(1)).await;
        let mark = logger.mark();
        refuse_create_session(&session).await;
        assert_one_report(
            &logger.since(mark),
            "CreateSession BadTcpEndpointUrlInvalid=2, ActivateSession BadIdentityTokenInvalid=1",
        );

        let _ = session.disconnect().await;
    });
    drop(client_rt);

    handle.cancel();
    server_rt.shutdown_timeout(LIVENESS);
}
