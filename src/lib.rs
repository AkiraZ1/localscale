use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub fn health_response() -> &'static str {
    r#"{"status":"ok","service":"localscale"}"#
}

pub fn configuration_html() -> &'static str {
    r#"<!doctype html>
<html lang="en"><meta charset="utf-8"><title>LocalScale</title>
<body><h1>LocalScale</h1><p>Local service is running.</p></body></html>"#
}

pub fn serve(listener: TcpListener) -> std::io::Result<()> {
    for stream in listener.incoming() {
        handle_connection(stream?)?;
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = [0_u8; 4096];
    let size = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..size]);
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    let (status, content_type, body) = match path {
        "/health" => ("200 OK", "application/json", health_response()),
        "/" | "/config" => ("200 OK", "text/html; charset=utf-8", configuration_html()),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found"),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{configuration_html, health_response};

    #[test]
    fn health_endpoint_returns_ok_json() {
        assert_eq!(health_response(), r#"{"status":"ok","service":"localscale"}"#);
    }

    #[test]
    fn configuration_page_has_product_title() {
        assert!(configuration_html().contains("<title>LocalScale</title>"));
    }
}
