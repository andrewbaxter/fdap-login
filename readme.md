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
     "fdap_base_url": "http://127.0.0.1:64116",
     // Token for accessing FDAP server
     "fdap_token": "MYTOKEN",
     // Path to dir containing additional assets for login screen: `style.css`,
     // `script.js` (optional)
     "static_dir": "/srv/oidc",
   }
   ```

2. Add the following user to your OpenFDAP config

   ```jsonc
   {
     "users": {
       "MYTOKEN": [
         {
           "action": {
             "read": true,
             "write": false,
           },
           "path": [
             { "string": "user" },
             "wildcard",
             { "string": "fdap-oidc" },
           ],
         },
       ],
     },
   }
   ```

3. Add the following to the FDAP database for each user (at `/user/X)

   ```jsonc
   {
     "fdap-oidc": {
       // Replace the value with the user's hashed password in PHC format:
       // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
       "password": "PHC_PASSWORD_HASH",
     },
   }
   ```

4. Run `fdap-oidc /path/to/config.json`
