//! Authentication configuration, token, and secure-store modules.

#[cfg(target_os = "linux")]
pub mod authorization_output;
pub mod config;
pub mod device_output;
pub mod host;
#[cfg(target_os = "linux")]
pub mod native_browser;
pub mod native_callback;
pub mod native_https;
pub mod oauth;
#[cfg(feature = "config-fixture")]
pub mod oauth_host;
pub mod pkce;
pub mod request_body;
pub mod store;
#[cfg(feature = "config-fixture")]
pub mod store_host;
pub mod token;
