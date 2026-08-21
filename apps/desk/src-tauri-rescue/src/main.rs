#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};
use tauri::{
    Url, WebviewUrl,
    webview::{NewWindowResponse, WebviewWindowBuilder},
};

const RESCUE_UI_URL: &str = "http://127.0.0.1:4173/";
const STARTUP_DEADLINE: Duration = Duration::from_secs(90);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
const MAX_PROBE_RESPONSE_BYTES: usize = 16 * 1024;

fn allowed_rescue_navigation(url: &Url) -> bool {
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(4173)
        && url.username().is_empty()
        && url.password().is_none()
}

fn valid_rescue_ui_response(response: &[u8]) -> bool {
    if response.is_empty() || response.len() > MAX_PROBE_RESPONSE_BYTES {
        return false;
    }
    let Ok(response) = std::str::from_utf8(response) else {
        return false;
    };
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    let mut lines = headers.lines();
    if !matches!(lines.next(), Some("HTTP/1.0 200 OK" | "HTTP/1.1 200 OK")) {
        return false;
    }
    let headers: Vec<&str> = lines.collect();
    let header_value = |expected_name: &str| {
        headers.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then_some(value.trim_ascii())
        })
    };
    header_value("Content-Security-Policy")
        .is_some_and(|value| value.starts_with("default-src 'none';"))
        && header_value("Content-Type") == Some("text/html")
        && header_value("X-Frame-Options") == Some("DENY")
        && header_value("X-Content-Type-Options") == Some("nosniff")
        && body.contains("<script type=\"module\"")
        && body.contains("./assets/")
        && body.contains("<div id=\"root\"></div>")
}

fn rescue_ui_ready_once() -> bool {
    let rescue_ui_address = SocketAddr::from(([127, 0, 0, 1], 4173));
    let Ok(mut stream) = TcpStream::connect_timeout(&rescue_ui_address, PROBE_TIMEOUT) else {
        return false;
    };
    if stream.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream
            .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1:4173\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(length) if response.len() + length <= MAX_PROBE_RESPONSE_BYTES => {
                response.extend_from_slice(&chunk[..length]);
            }
            Ok(_) | Err(_) => return false,
        }
    }
    valid_rescue_ui_response(&response)
}

fn wait_for_rescue_ui() -> std::io::Result<()> {
    let started = Instant::now();
    while started.elapsed() < STARTUP_DEADLINE {
        if rescue_ui_ready_once() {
            return Ok(());
        }
        thread::sleep(PROBE_INTERVAL);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Rescue UI did not become ready",
    ))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_rescue_ui()?;
    tauri::Builder::default()
        .setup(|app| {
            let rescue_url: Url = RESCUE_UI_URL.parse()?;
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(rescue_url))
                .title("KernAid Rescue")
                .fullscreen(true)
                .decorations(false)
                .focused(true)
                .incognito(true)
                .devtools(false)
                .zoom_hotkeys_enabled(false)
                .disable_drag_drop_handler()
                .on_navigation(allowed_rescue_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .on_download(|_, _| false)
                .build()?;
            Ok(())
        })
        // This binary intentionally registers no invoke handler.  Together
        // with the no-permission capability above, the remote loopback origin
        // cannot dispatch Resident or plugin commands.
        .run(tauri::generate_context!())?;
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("KernAid Rescue shell failed closed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_is_pinned_to_the_exact_loopback_origin() {
        for allowed in [
            "http://127.0.0.1:4173/",
            "http://127.0.0.1:4173/assets/index.js",
            "http://127.0.0.1:4173/api/inventory",
        ] {
            let url: Url = allowed.parse().expect("fixed URL");
            assert!(allowed_rescue_navigation(&url));
        }

        for denied in [
            "https://127.0.0.1:4173/",
            "http://localhost:4173/",
            "http://127.0.0.1:4174/",
            "http://127.0.0.1/",
            "http://user@127.0.0.1:4173/",
            "file:///opt/kernaid/desk/index.html",
            "https://example.invalid/",
        ] {
            let url: Url = denied.parse().expect("fixed URL");
            assert!(!allowed_rescue_navigation(&url));
        }
    }

    #[test]
    fn startup_probe_requires_the_bundle_and_security_headers() {
        let response = b"HTTP/1.0 200 OK\r\n\
Content-Security-Policy: default-src 'none'; script-src 'self'\r\n\
Content-Type: text/html\r\n\
X-Frame-Options: DENY\r\n\
X-Content-Type-Options: nosniff\r\n\
\r\n\
<script type=\"module\" src=\"./assets/index.js\"></script>\
<div id=\"root\"></div>";
        assert!(valid_rescue_ui_response(response));
        for invalid in [
            response
                .as_slice()
                .strip_prefix(b"HTTP/1.0 200 OK\r\n")
                .expect("fixed response has the status line"),
            response
                .as_slice()
                .strip_suffix(b"<div id=\"root\"></div>")
                .expect("fixed response has the root element"),
            &b"HTTP/1.0 200 OK\r\n\r\n<div id=\"root\"></div>"[..],
        ] {
            assert!(!valid_rescue_ui_response(invalid));
        }
        assert!(!valid_rescue_ui_response(&vec![
            b'x';
            MAX_PROBE_RESPONSE_BYTES + 1
        ]));
    }
}
