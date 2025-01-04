use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct User {
    /// Password hash in PHC format:
    /// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    pub password: String,
}
