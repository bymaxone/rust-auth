//! The built-in OAuth providers. Each implements [`crate::traits::OAuthProvider`] over the
//! injected [`crate::traits::HttpClient`] — no provider embeds an HTTP client, so the base
//! `oauth` feature stays transport-free. The bundled `reqwest`-backed transport lives behind
//! the separate `oauth-reqwest` feature.

mod google;
#[cfg(feature = "oauth-reqwest")]
mod reqwest_client;

pub use google::GoogleOAuthProvider;
#[cfg(feature = "oauth-reqwest")]
pub use reqwest_client::ReqwestHttpClient;
