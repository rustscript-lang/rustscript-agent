#[path = "support/opaque_chat_stream.rs"]
#[allow(dead_code)]
mod opaque_chat_stream;

#[path = "cases/codex_responses_rss_entry_tests.rs"]
mod codex_responses_rss_entry_tests;

#[path = "cases/provider_access_failure_tests.rs"]
mod provider_access_failure_tests;

#[path = "cases/provider_auth_rss_entry_tests.rs"]
mod provider_auth_rss_entry_tests;

#[path = "cases/provider_default_opaque_tests.rs"]
mod provider_default_opaque_tests;

#[path = "cases/provider_opaque_bridge_tests.rs"]
mod provider_opaque_bridge_tests;

#[path = "cases/provider_openai_opaque_tests.rs"]
mod provider_openai_opaque_tests;
