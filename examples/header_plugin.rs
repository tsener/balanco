//! A trusted, compiled plugin. Register Arc::new(DeviceHeaders) in the host's State::new call.
use balanco::{
    Error,
    http_plugin::{Context, HeaderMap, HeaderValue, HttpPlugin, Phase},
};

struct DeviceHeaders;
impl HttpPlugin for DeviceHeaders {
    fn transform(
        &self,
        phase: Phase,
        context: &Context<'_>,
        headers: &mut HeaderMap,
    ) -> Result<(), Error> {
        if phase == Phase::Request && context.path.starts_with("/devices/") {
            headers.insert("x-device-gateway", HeaderValue::from_static("balanco"));
        }
        Ok(())
    }
}

fn main() -> Result<(), Error> {
    let context = Context {
        peer: "192.0.2.1:1234".parse()?,
        backend: "127.0.0.1:9000".parse()?,
        scheme: "https",
        method: "GET",
        path: "/devices/example",
        sni: None,
        status: None,
    };
    let mut headers = HeaderMap::new();
    DeviceHeaders.transform(Phase::Request, &context, &mut headers)?;
    assert_eq!(headers["x-device-gateway"], "balanco");
    Ok(())
}
