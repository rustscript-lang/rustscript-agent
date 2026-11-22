#[path = "support/opaque_chat_stream.rs"]
mod opaque_chat_stream;

#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
mod provider_opaque_fixture;

#[path = "cases/provider_401_refresh_loop_tests.rs"]
mod provider_401_refresh_loop_tests;

#[path = "cases/provider_concurrent_generation_loop_tests.rs"]
mod provider_concurrent_generation_loop_tests;

#[path = "cases/provider_expired_refresh_loop_tests.rs"]
mod provider_expired_refresh_loop_tests;

#[path = "cases/provider_opaque_loop_tests.rs"]
mod provider_opaque_loop_tests;

#[path = "cases/provider_opaque_tool_loop_tests.rs"]
mod provider_opaque_tool_loop_tests;

#[path = "cases/provider_quota_loop_tests.rs"]
mod provider_quota_loop_tests;

#[path = "cases/real_tool_continuation_tests.rs"]
mod real_tool_continuation_tests;
