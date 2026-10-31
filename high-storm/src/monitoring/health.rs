use metrics::{counter, gauge};

use super::{names, refresh::unix_now};

/// A background task that publishes metrics. If one dies or keeps failing, the
/// gauges it owns freeze or go idle and their alerts cannot fire, so each task
/// reports on itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MonitoringTask {
    Refresh,
    DbGauges,
    ElementsProbe,
    StormEyeProbe,
}

impl MonitoringTask {
    fn as_str(self) -> &'static str {
        match self {
            Self::Refresh => "refresh",
            Self::DbGauges => "db_gauges",
            Self::ElementsProbe => "elements_probe",
            Self::StormEyeProbe => "storm_eye_probe",
        }
    }
}

/// Set directly at the end of every pass rather than retained, so a task that
/// stops goes stale and then drops out.
pub(super) fn record_task_run(task: MonitoringTask) {
    gauge!(names::MONITORING_TASK_LAST_RUN, "task" => task.as_str()).set(unix_now() as f64);
}

/// A read that failed, which leaves the gauges it feeds at their last values.
pub(super) fn record_task_error(task: MonitoringTask) {
    counter!(names::MONITORING_TASK_ERRORS, "task" => task.as_str()).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn reports_each_task_by_name() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_task_run(MonitoringTask::DbGauges);
            record_task_error(MonitoringTask::StormEyeProbe);
        });

        let rendered = recorder.handle().render();
        assert!(rendered.contains(
            r#"high_storm_monitoring_task_last_run_timestamp_seconds{task="db_gauges"}"#
        ));
        assert!(
            rendered
                .contains(r#"high_storm_monitoring_task_errors_total{task="storm_eye_probe"} 1"#)
        );
    }
}
