use std::time::Duration;

/// Fixture watchdog for a valid debug gateway to become ready. The real binary
/// compiles the bundled guest graph before binding. Cold runs took 52–56s;
/// under contention a listener took 145s and the post-construction plugin
/// refusal diagnostic arrived at 255s. Leave headroom for parallel startup
/// without carrying it into request, source-refusal, or shutdown deadlines.
pub const GATEWAY_READY_BUDGET: Duration = Duration::from_secs(300);

/// Persistent managed and signed-restart fixtures also initialize their
/// on-disk store before binding. A managed cold start reached the real
/// listener at 69s on a quieter host; prior contended managed and signed
/// starts outlasted the 360s probe and 300s watchdog, respectively. Give just
/// these listener observations more headroom, not the requests or shutdown.
#[allow(dead_code)] // Other integration targets only use the ordinary budget.
pub const PERSISTENT_GATEWAY_READY_BUDGET: Duration =
    Duration::from_secs(GATEWAY_READY_BUDGET.as_secs() + 180);
