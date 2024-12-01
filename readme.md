This is a very minimal OIDC provider for use with FDAP.

It retrieves user data from FDAP to validate the login, and sends a response containing only an `id_token` and only the FDAP user id as the `sub` in the `id_token`. This should be sufficient for other applications working with FDAP to retrieve information from the FDAP server independently.

The login form is unstyled - you should prepre a directory with CSS (`style.css`) and other assets (optionally also `script.js`) if you want styling.

# Installation

`cargo build`

# Use

1. Prepare a config file:

```jsonc
{
    // Socket address to bind to
    "bind_addr": "0:8001",
    // Base URL of FDAP server
    "fdap_base_url": Uri,
    // Token for accessing FDAP server
    fdap_token: String,
    // Path to dir containing additional assets for login screen: `style.css`,
    // `script.js`
    static_dir: Option<PathBuf>,
}
```
