//! An aggregated report of refused session-establishment requests.
//!
//! A refused CreateSession or ActivateSession keeps its connection open, so a
//! client can repeat it at the rate the network carries. A log line per refusal
//! would let each request buy one log write, so refusals are counted per
//! service and status code and reported in at most one warning per
//! [`REFUSAL_REPORT_INTERVAL`].

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use opcua_types::StatusCode;
use parking_lot::Mutex;
use tracing::warn;

/// The shortest time between two refusal reports.
pub(crate) const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// A session-establishment service whose refusals are reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum EstablishmentService {
    CreateSession,
    ActivateSession,
}

impl EstablishmentService {
    pub(crate) fn name(self) -> &'static str {
        match self {
            EstablishmentService::CreateSession => "CreateSession",
            EstablishmentService::ActivateSession => "ActivateSession",
        }
    }
}

/// The refusal counts one report names, ordered by service and status code.
type Report = Vec<(EstablishmentService, StatusCode, u64)>;

#[derive(Default)]
struct RefusalCounts {
    previous_report: Option<Instant>,
    counts: HashMap<(EstablishmentService, StatusCode), u64>,
}

/// Count one refusal at `now`, and return the counts to report when no report
/// was made within [`REFUSAL_REPORT_INTERVAL`] before it. Reporting restarts
/// the counts.
fn record_refusal(
    state: &mut RefusalCounts,
    service: EstablishmentService,
    status: StatusCode,
    now: Instant,
) -> Option<Report> {
    *state.counts.entry((service, status)).or_insert(0) += 1;
    let due = match state.previous_report {
        None => true,
        Some(previous) => now.saturating_duration_since(previous) >= REFUSAL_REPORT_INTERVAL,
    };
    if !due {
        return None;
    }
    state.previous_report = Some(now);
    let mut report: Report = state
        .counts
        .drain()
        .map(|((service, status), count)| (service, status, count))
        .collect();
    report.sort_by_key(|(service, status, _)| (*service, status.bits()));
    Some(report)
}

fn format_report(report: &Report) -> String {
    report
        .iter()
        .map(|(service, status, count)| format!("{} {status}={count}", service.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The refusal report of one server's session manager.
#[derive(Default)]
pub(crate) struct RefusalReport {
    state: Mutex<RefusalCounts>,
}

impl RefusalReport {
    /// Count a refusal of `service` with `status`, writing the report when one
    /// is due.
    pub(crate) fn record(&self, service: EstablishmentService, status: StatusCode) {
        let report = {
            let mut state = self.state.lock();
            record_refusal(&mut state, service, status, Instant::now())
        };
        if let Some(report) = report {
            warn!(
                "Refused session establishment requests since the previous report, per service and status code: {}",
                format_report(&report)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATE: EstablishmentService = EstablishmentService::CreateSession;
    const ACTIVATE: EstablishmentService = EstablishmentService::ActivateSession;

    #[test]
    fn first_refusal_reports_at_once() {
        let mut state = RefusalCounts::default();
        let report = record_refusal(
            &mut state,
            CREATE,
            StatusCode::BadTcpEndpointUrlInvalid,
            Instant::now(),
        );
        assert_eq!(
            report,
            Some(vec![(CREATE, StatusCode::BadTcpEndpointUrlInvalid, 1)])
        );
        assert!(state.counts.is_empty());
    }

    #[test]
    fn refusals_within_the_interval_are_only_counted() {
        let start = Instant::now();
        let mut state = RefusalCounts::default();
        record_refusal(
            &mut state,
            CREATE,
            StatusCode::BadTcpEndpointUrlInvalid,
            start,
        );
        let just_inside = start + REFUSAL_REPORT_INTERVAL - Duration::from_millis(1);
        for at in [start, start + Duration::from_secs(1), just_inside] {
            assert_eq!(
                record_refusal(
                    &mut state,
                    ACTIVATE,
                    StatusCode::BadIdentityTokenInvalid,
                    at
                ),
                None
            );
        }
        assert_eq!(
            state
                .counts
                .get(&(ACTIVATE, StatusCode::BadIdentityTokenInvalid)),
            Some(&3)
        );
    }

    #[test]
    fn refusal_at_the_interval_reports_the_counts_since_the_previous_report() {
        let start = Instant::now();
        let mut state = RefusalCounts::default();
        record_refusal(
            &mut state,
            CREATE,
            StatusCode::BadTcpEndpointUrlInvalid,
            start,
        );
        record_refusal(
            &mut state,
            ACTIVATE,
            StatusCode::BadIdentityTokenInvalid,
            start,
        );
        record_refusal(&mut state, CREATE, StatusCode::BadNonceInvalid, start);
        let report = record_refusal(
            &mut state,
            ACTIVATE,
            StatusCode::BadIdentityTokenInvalid,
            start + REFUSAL_REPORT_INTERVAL,
        );
        assert_eq!(
            report,
            Some(vec![
                (CREATE, StatusCode::BadNonceInvalid, 1),
                (ACTIVATE, StatusCode::BadIdentityTokenInvalid, 2),
            ])
        );
        assert_eq!(state.previous_report, Some(start + REFUSAL_REPORT_INTERVAL));
        assert!(state.counts.is_empty());
    }

    #[test]
    fn a_clock_reading_before_the_previous_report_is_not_due() {
        let start = Instant::now() + Duration::from_secs(5);
        let mut state = RefusalCounts::default();
        record_refusal(&mut state, CREATE, StatusCode::BadTooManySessions, start);
        assert_eq!(
            record_refusal(
                &mut state,
                CREATE,
                StatusCode::BadTooManySessions,
                start - Duration::from_secs(1)
            ),
            None
        );
    }

    #[test]
    fn report_names_each_service_status_code_and_count() {
        let report = vec![
            (CREATE, StatusCode::BadTcpEndpointUrlInvalid, 3),
            (ACTIVATE, StatusCode::BadIdentityTokenInvalid, 1),
        ];
        assert_eq!(
            format_report(&report),
            "CreateSession BadTcpEndpointUrlInvalid=3, ActivateSession BadIdentityTokenInvalid=1"
        );
    }
}
