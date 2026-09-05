use localscale_agent::serve;
use std::env;
use std::net::TcpListener;
use std::process::{Command, Stdio};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let no_open = args.iter().any(|arg| arg == "--no-open");
    let port = args
        .windows(2)
        .find(|pair| pair[0] == "--port")
        .and_then(|pair| pair[1].parse::<u16>().ok())
        .unwrap_or(8765);

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let address = listener.local_addr()?;
    let url = format!("http://{}/", address);
    println!("LocalScale web: {url}");

    if !no_open {
        open_browser(&url);
    }

    serve(listener)
}

fn open_browser(url: &str) {
    #[cfg(target_os = "linux")]
    let command = ("xdg-open", vec![url]);
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let command = ("cmd", vec!["/C", "start", "", url]);

    let _ = Command::new(command.0)
        .args(command.1)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}
