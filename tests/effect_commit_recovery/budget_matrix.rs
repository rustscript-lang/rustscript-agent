use super::*;
#[cfg(feature = "workspace-io-fault")]
#[tokio::test(flavor = "multi_thread")]
async fn real_formal_128_row_page_and_exact_cursor_counts_preserve_all_retained_effects() {
    use rustscript_agent::effects::{ManagedEffectFault, ManagedEffectListRequest};
    let fixture = ManagedFixture::new(|_| {});
    fs::write(fixture.root.join("workspace/page.txt"), b"bounded").unwrap();
    fixture
        .state
        .service()
        .set_run_limits(
            rustscript_agent::config::RunLimits::new(
                64,
                128,
                4 * 1024 * 1024,
                fixture.root.join("workspace"),
            )
            .unwrap(),
        )
        .unwrap();
    let mut expected = std::collections::BTreeSet::new();
    let mut workspace = None;
    for batch in 0..5 {
        let calls=(0..25).map(|index|json!({"id":format!("page-{batch}-{index}"),"name":"read_file","arguments":{"path":"page.txt"}})).collect::<Vec<_>>();
        let run = fixture.calls(calls).await;
        for index in 0..25 {
            let record = fixture
                .state
                .persistence()
                .unwrap()
                .managed_effect_get(&ManagedFixture::request(
                    &run,
                    &format!("page-{batch}-{index}"),
                ))
                .unwrap()
                .expect("every selected original RSS call must create its own durable record");
            assert!(
                record.outcome.is_some(),
                "page fixture must use real final RSS observations"
            );
            workspace = Some(record.identity.workspace.workspace_id.clone());
            assert!(expected.insert(record.effect_id));
        }
    }
    for index in 0..3 {
        fixture
            .state
            .service()
            .inject_managed_effect_fault(ManagedEffectFault::AfterIntent)
            .unwrap();
        let id = format!("intent-{index}");
        let run = fixture
            .calls(vec![
                json!({"id":id,"name":"read_file","arguments":{"path":"page.txt"}}),
            ])
            .await;
        let record = fixture
            .state
            .persistence()
            .unwrap()
            .managed_effect_get(&ManagedFixture::request(&run, &id))
            .unwrap()
            .expect(
                "remaining page entries are durable pre-execution intents, not fabricated rows",
            );
        assert!(record.outcome.is_none());
        assert!(expected.insert(record.effect_id));
    }
    assert_eq!(expected.len(), 128);
    let request = ManagedEffectListRequest {
        workspace_id: workspace.unwrap(),
        after_effect_id: None,
        limit: 128,
    };
    let page = fixture
        .state
        .service()
        .query_managed_effects(request.clone())
        .unwrap();
    assert_eq!(page.entries.len(), 128);
    assert!(!page.has_more);
    assert!(page.next_cursor.is_none());
    assert!(serde_json::to_vec(&page).unwrap().len() < 1024 * 1024);
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.effect_id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    let first = fixture
        .state
        .service()
        .query_managed_effects(ManagedEffectListRequest {
            limit: 127,
            ..request.clone()
        })
        .unwrap();
    assert_eq!(first.entries.len(), 127);
    assert!(first.has_more);
    let last = fixture
        .state
        .service()
        .query_managed_effects(ManagedEffectListRequest {
            after_effect_id: first.next_cursor.clone(),
            ..request.clone()
        })
        .unwrap();
    assert_eq!(last.entries.len(), 1);
    assert!(!last.has_more);
    let collected = first
        .entries
        .into_iter()
        .chain(last.entries)
        .map(|entry| entry.effect_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(collected, expected);
    let fixture = fixture.reopen().await;
    let page = fixture
        .state
        .service()
        .query_managed_effects(request)
        .unwrap();
    assert_eq!(page.entries.len(), 128);
    assert_eq!(
        page.entries
            .into_iter()
            .map(|entry| entry.effect_id)
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    fixture.state.service().shutdown().await.unwrap();
}
