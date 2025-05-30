use {
    http::Uri,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        net::SocketAddr,
        path::PathBuf,
    },
};

pub struct SerdeUrl(pub Uri);

impl JsonSchema for SerdeUrl {
    fn schema_name() -> String {
        return "Url".to_string();
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        return String::json_schema(gen);
    }
}

impl Serialize for SerdeUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return http_serde::uri::serialize(&self.0, serializer);
    }
}

impl<'d> Deserialize<'d> for SerdeUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'d> {
        return Ok(Self(http_serde::uri::deserialize(deserializer)?));
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Config {
    /// Socket address to bind to
    pub bind_addr: SocketAddr,
    /// Base URL of FDAP server
    pub fdap_base_url: SerdeUrl,
    /// Token for accessing FDAP server
    pub fdap_token: String,
    /// Path to dir containing additional assets for login screen: `style.css`,
    /// `script.js`
    #[serde(default)]
    pub static_dir: Option<PathBuf>,
    #[serde(default)]
    pub debug: bool,
}
