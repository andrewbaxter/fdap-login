use {
    http::{
        request::Parts,
        Uri,
    },
    htwrap::htserve::{
        self,
        forwarded::get_original_base_url,
    },
};

pub fn get_base_url(full_url: &Uri, head: &Parts) -> Result<Uri, loga::Error> {
    let forwarded = htserve::forwarded::parse_all_forwarded(&head.headers).unwrap_or_default();
    return Ok(get_original_base_url(full_url, &forwarded)?);
}
