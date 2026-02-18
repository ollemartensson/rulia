use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = env::args().skip(1);
    let mut check = false;
    let mut path: Option<String> = None;

    for arg in args {
        if arg == "--check" {
            check = true;
        } else if path.is_none() {
            path = Some(arg);
        } else {
            return usage("unexpected argument");
        }
    }

    let path = match path {
        Some(p) => p,
        None => return usage("missing file"),
    };

    let text = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("rulia-fmt: failed to read {}: {}", path, err);
            return ExitCode::from(1);
        }
    };

    if check {
        match rulia_fmt::check(&text) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        }
    } else {
        match rulia_fmt::format(&text) {
            Ok(formatted) => {
                print!("{}", formatted);
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        }
    }
}

fn usage(message: &str) -> ExitCode {
    eprintln!("rulia-fmt: {}", message);
    eprintln!("usage: rulia-fmt [--check] <file>");
    ExitCode::from(2)
}
