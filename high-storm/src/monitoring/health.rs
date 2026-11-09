use std::{collections::BTreeMap, sync::Mutex};

use metrics::{counter, gauge};

use super::{names, refresh::unix_now};

/// Each task's last finished pass, or its start until it finishes one.
static LAST_RUNS: Mutex<BTreeMap<&'static str, f64>> = Mutex::new(BTreeMap::new());

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

/// Counts from the task's start, so one that never finishes a pass goes stale.
pub(super) fn record_task_started(task: MonitoringTask) {
    record_task_run(task);
}

pub(super) fn record_task_run(task: MonitoringTask) {
    let now = unix_now() as f64;
    gauge!(names::MONITORING_TASK_LAST_RUN, "task" => task.as_str()).set(now);
    LAST_RUNS
        .lock()
        .expect("task runs lock poisoned")
        .insert(task.as_str(), now);
}

/// Called on every scrape rather than by the tasks, so a task that stops keeps
/// reporting its last run and stays stale instead of going idle and dropping out.
pub(super) fn record_task_runs() {
    let last_runs = LAST_RUNS.lock().expect("task runs lock poisoned");
    for (&task, &last_run) in last_runs.iter() {
        gauge!(names::MONITORING_TASK_LAST_RUN, "task" => task).set(last_run);
    }
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

    #[test]
    fn republishes_a_task_that_never_finished_a_pass() {
        record_task_started(MonitoringTask::ElementsProbe);
        // A recorder that has not seen the task, as after the gauge went idle.
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, record_task_runs);

        assert!(recorder.handle().render().contains(
            r#"high_storm_monitoring_task_last_run_timestamp_seconds{task="elements_probe"}"#
        ));
    }
}
