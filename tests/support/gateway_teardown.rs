use rustscript_agent::AgentGatewayState;
use rustscript_agent::gateway::store::GatewayPersistence;
use std::sync::Arc;
use std::time::Duration;

/// Retain the storage owner until every service/worker producer has retired.
/// Taking the native value, then dropping it on an awaited blocking task,
/// proves that its actual storage-worker join finished before root deletion.
pub struct GatewayTeardown {
    persistence: Arc<GatewayPersistence>,
}

impl GatewayTeardown {
    pub fn observe(state: &AgentGatewayState) -> Self {
        Self {
            persistence: state.persistence().expect("fixture persistence"),
        }
    }

    #[cfg(feature = "config-fixture")]
    pub fn storage_owner_alive(&self) -> bool {
        Arc::strong_count(&self.persistence) > 1
    }

    pub async fn finish(self) {
        tokio::time::timeout(Duration::from_secs(2), async move {
            let mut owner = self.persistence;
            let persistence = loop {
                match Arc::try_unwrap(owner) {
                    Ok(persistence) => break persistence,
                    Err(retained) => owner = retained,
                }
                tokio::task::yield_now().await;
            };
            tokio::task::spawn_blocking(move || drop(persistence))
                .await
                .expect("storage owner drop and worker join");
        })
        .await
        .expect("fixture cleanup must retire producers and join storage before directory removal");
    }
}

#[cfg(feature = "config-fixture")]
pub struct TerminalCleanupPause {
    entered: std::sync::mpsc::Receiver<()>,
    completed: std::sync::mpsc::Receiver<bool>,
    release: Option<std::sync::mpsc::Sender<()>>,
}

#[cfg(feature = "config-fixture")]
impl TerminalCleanupPause {
    pub fn install(persistence: &GatewayPersistence) -> Self {
        let (entered_sender, entered) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (completed_sender, completed) = std::sync::mpsc::channel();
        persistence.inject_approval_expire_hook(
            move || {
                entered_sender.send(()).expect("expiry observer receiver");
                released
                    .recv_timeout(Duration::from_secs(2))
                    .expect("fixture must release the post-terminal expiry worker");
            },
            move |success| {
                let _ = completed_sender.send(success);
            },
        );
        Self {
            entered,
            completed,
            release: Some(release),
        }
    }

    pub fn wait_entered(&self) {
        self.entered
            .recv_timeout(Duration::from_secs(2))
            .expect("post-terminal expiry observer must be reached");
    }

    pub fn assert_completed(&self) {
        assert_eq!(
            self.completed.try_recv(),
            Ok(true),
            "the same post-terminal expiry must succeed before storage joins"
        );
    }

    pub fn release(&mut self) {
        if let Some(sender) = self.release.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(feature = "config-fixture")]
impl Drop for TerminalCleanupPause {
    fn drop(&mut self) {
        self.release();
    }
}
