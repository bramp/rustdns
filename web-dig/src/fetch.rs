use std::time::Duration;
use wasm_bindgen::{JsCast, closure::Closure};

struct FetchTimeout {
    window: web_sys::Window,
    handle: i32,
    _callback: Closure<dyn FnMut()>,
}

impl Drop for FetchTimeout {
    fn drop(&mut self) {
        self.window.clear_timeout_with_handle(self.handle);
    }
}

fn abort_after(
    window: &web_sys::Window,
    timeout: Duration,
) -> Result<(web_sys::AbortController, FetchTimeout), String> {
    let controller = web_sys::AbortController::new()
        .map_err(|error| format!("failed to create abort controller: {error:?}"))?;
    let abort_controller = controller.clone();
    let callback = Closure::wrap(Box::new(move || abort_controller.abort()) as Box<dyn FnMut()>);
    let timeout_ms = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
    let handle = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            timeout_ms,
        )
        .map_err(|error| format!("failed to set request deadline: {error:?}"))?;
    Ok((
        controller,
        FetchTimeout {
            window: window.clone(),
            handle,
            _callback: callback,
        },
    ))
}

fn fetch_error(
    signal: &web_sys::AbortSignal,
    context: &str,
    error: &wasm_bindgen::JsValue,
) -> String {
    if signal.aborted() {
        "request timed out".to_string()
    } else {
        format!("{context}: {error:?}")
    }
}

/// Sends an HTTP request with an optional binary body and receives binary response bytes.
pub async fn fetch_binary(
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(Vec<u8>, u16), String> {
    let window = web_sys::window().ok_or_else(|| "no global `window` exists".to_string())?;
    let (controller, _timeout) = abort_after(&window, timeout)?;
    let signal = controller.signal();

    let opts = web_sys::RequestInit::new();
    if body.is_some() {
        opts.set_method("POST");
    } else {
        opts.set_method("GET");
    }
    opts.set_mode(web_sys::RequestMode::Cors);
    opts.set_signal(Some(&signal));

    if let Some(bytes) = body {
        let uint8_arr = js_sys::Uint8Array::from(bytes);
        opts.set_body(&uint8_arr.into());
    }

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("failed to create request: {e:?}"))?;

    let req_headers = request.headers();
    for &(key, val) in headers {
        req_headers
            .set(key, val)
            .map_err(|e| format!("failed to set header {key}: {e:?}"))?;
    }

    let resp_value = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| {
            fetch_error(
                &signal,
                "network request failed (check CORS or network)",
                &e,
            )
        })?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|e| format!("response is not a web_sys::Response: {e:?}"))?;

    let status = resp.status();
    if !(200..=299).contains(&status) {
        return Err(format!("HTTP error {status}: {}", resp.status_text()));
    }

    let buffer_promise = resp
        .array_buffer()
        .map_err(|e| format!("failed to get array buffer: {e:?}"))?;
    let buffer_val = wasm_bindgen_futures::JsFuture::from(buffer_promise)
        .await
        .map_err(|e| fetch_error(&signal, "failed to read array buffer", &e))?;

    let uint8_arr = js_sys::Uint8Array::new(&buffer_val);
    Ok((uint8_arr.to_vec(), status))
}

/// Sends an HTTP GET request and receives response text.
pub async fn fetch_text(
    url: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(String, u16), String> {
    let window = web_sys::window().ok_or_else(|| "no global `window` exists".to_string())?;
    let (controller, _timeout) = abort_after(&window, timeout)?;
    let signal = controller.signal();

    let opts = web_sys::RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(web_sys::RequestMode::Cors);
    opts.set_signal(Some(&signal));

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("failed to create request: {e:?}"))?;

    let req_headers = request.headers();
    for &(key, val) in headers {
        req_headers
            .set(key, val)
            .map_err(|e| format!("failed to set header {key}: {e:?}"))?;
    }

    let resp_value = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| {
            fetch_error(
                &signal,
                "network request failed (check CORS or network)",
                &e,
            )
        })?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|e| format!("response is not a web_sys::Response: {e:?}"))?;

    let status = resp.status();
    if !(200..=299).contains(&status) {
        return Err(format!("HTTP error {status}: {}", resp.status_text()));
    }

    let text_promise = resp
        .text()
        .map_err(|e| format!("failed to get text response: {e:?}"))?;
    let text_val = wasm_bindgen_futures::JsFuture::from(text_promise)
        .await
        .map_err(|e| fetch_error(&signal, "failed to read text", &e))?;

    let text = text_val
        .as_string()
        .ok_or_else(|| "text response was not a string".to_string())?;
    Ok((text, status))
}
