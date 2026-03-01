![Screenshot](./screenshot.avif)

This is a very minimal OIDC provider for use with [FDAP](https://github.com/andrewbaxter/openfdap).

It retrieves user data from FDAP to validate the login, and sends a response containing only an `id_token` and only the FDAP user id as the `sub` in the `id_token`. This should be sufficient for other applications working with FDAP to retrieve information from the FDAP server independently.

The login form is unstyled - you should prepre a directory with CSS (`style.css`) and other assets (optionally also `script.js`) if you want styling. There's a [reference style](https://github.com/andrewbaxter/fdap-oidc-style) shown in the screenshot.

# Installation

`cargo build`

# Use

1. Create a secret (any random string) for fdap-login to use to read user data from fdap. A placeholder is used below that you should replace: `MYTOKEN`.

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

   `static_dir` should be the path to your style, e.g. the reference style linked above.

1. Add the following user to your OpenFDAP config to allow fdap-login to read user data.

   ```jsonc
   {
     "users": {
       "MYTOKEN": [
         {
           // What fdap-login can access in the fdap-database
           "path": [
             { "string": "user" },
             "wildcard",
             { "string": "fdap-oidc" },
           ],
           // What it can do to the data
           "action": {
             "read": true,
             "write": false,
           },
         },
       ],
     },
   }
   ```

1. Add the following to the FDAP database for each user (at `/user/X)

   ```jsonc
   {
     "fdap-oidc": {
       // Replace the value with the user's hashed password in PHC format:
       // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
       //
       // You can generate this with `fdap-login hash-password`
       "password": "PHC_PASSWORD_HASH",
     },
   }
   ```

1. Run `fdap-oidc /path/to/config.json`
