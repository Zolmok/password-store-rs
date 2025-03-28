use clap::{arg, Command as ClapCommand};
use is_executable::IsExecutable;
use once_cell::sync::Lazy;
use std::{
    env, fs,
    io::{self, Write},
    path::Path,
    process::{exit, Command, Stdio},
};

static HOME: Lazy<String> = Lazy::new(|| match env::var("HOME") {
    Ok(val) => val,
    Err(_) => panic!("Error: $HOME is not set."),
});

const PREFIX: Lazy<String> = Lazy::new(|| match env::var("PASSWORD_STORE_DIR") {
    Ok(val) => val,
    Err(_) => format!("{}/.password-store", HOME.to_string()),
});

fn cli() -> ClapCommand {
    ClapCommand::new("pass-rs")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("A password manager")
        .subcommand(
            ClapCommand::new("init")
                .about("Initialize new password storage and use gpg-id for encryption")
                .arg(arg!(<GPGID> "Specifies a GPG key identifier").value_name("gpg-id"))
                // Change from <subfolder> to [subfolder] to make it optional.
                .arg(arg!(-p --path [subfolder] "Specifies an optional subfolder")),
        )
        .subcommand(
            ClapCommand::new("add")
                .about("Add a new password")
                .arg(arg!(<PASS_NAME> "The name of the password entry").value_name("pass-name"))
                .arg(arg!([PASSWORD] "The password to store (if not provided, you will be prompted)").value_name("password"))
        )
        .subcommand(
            ClapCommand::new("find")
                .about("List passwords that match pass-names.")
                .arg(arg!(<PASS_NAMES> "Specifies a pass-name").value_name("pass-names"))
        )
        .subcommand(ClapCommand::new("ls").about("List passwords."))
        .subcommand(
            ClapCommand::new("show")
                .about("Show existing password and optionally put it on the clipboard. If put on the clipboard, it will be cleared in $CLIP_TIME seconds.")
                .arg(arg!(<PASS_NAME> "Specifies a pass-name").value_name("pass-name").required(false))
                .arg(arg!(-c --clip "Put the password on the clipboard (clears in $CLIP_TIME seconds)"))
        )
}

fn verify_file(file_path: &str) {
    if std::env::var("PASSWORD_STORE_SIGNING_KEY").is_err() {
        return;
    }

    if !Path::new(&(file_path.to_owned() + ".sig")).is_file() {
        eprintln!("Signature for {} does not exist.", file_path);
        exit(1);
    }

    let output = Command::new("gpg")
        .args(&[
            std::env::var("PASSWORD_STORE_GPG_OPTS").unwrap_or_default(),
            "--verify".to_string(),
            "--status-fd=1".to_string(),
            (file_path.to_owned() + ".sig"),
            file_path.to_string(),
        ])
        .stderr(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|_| {
            eprintln!("Failed to execute the 'gpg' command.");
            exit(1);
        });

    let output_string = String::from_utf8_lossy(&output.stdout);
    let fingerprints: Vec<&str> = output_string
        .lines()
        .filter_map(|line| {
            if line.starts_with("[GNUPG:] VALIDSIG") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    return Some(parts[3]);
                }
            }
            None
        })
        .collect();

    let signing_key_binding = std::env::var("PASSWORD_STORE_SIGNING_KEY").unwrap_or_default();
    let signing_key = signing_key_binding
        .split_whitespace()
        .filter(|&fingerprint| {
            fingerprint.len() == 40 && u64::from_str_radix(fingerprint, 16).is_ok()
        });

    let mut found = false;
    for fingerprint in signing_key {
        if fingerprints.iter().any(|&f| f.contains(fingerprint)) {
            found = true;
            break;
        }
    }

    if !found {
        eprintln!("Signature for {} is invalid.", file_path);
        exit(1);
    }
}

fn source_file(file_path: &str, args: &[String]) {
    let output = Command::new(file_path)
        .args(args)
        .output()
        .expect("Failed to execute command");

    println!("{}", String::from_utf8_lossy(&output.stdout));
}

fn cmd_add(pass_name: &str, maybe_password: Option<&str>) {
    // Ensure the password store directory exists.
    if !Path::new(&*PREFIX).exists() {
        eprintln!(
            "Error: Password store '{}' does not exist. Try \"pass init\".",
            &*PREFIX
        );
        exit(1);
    }

    // Determine the output file path for the new password.
    let passfile = format!("{}/{}.gpg", &*PREFIX, pass_name);

    // Read the GPG recipient from the .gpg-id file in the store.
    let gpg_id_file = format!("{}/.gpg-id", &*PREFIX);
    let recipient = match std::fs::read_to_string(&gpg_id_file) {
        Ok(content) => content.trim().to_string(),
        Err(e) => {
            eprintln!(
                "Error reading {}: {}. Is the store initialized?",
                gpg_id_file, e
            );
            exit(1);
        }
    };

    // Retrieve the password to store.
    let password = if let Some(p) = maybe_password {
        p.to_string()
    } else {
        println!("Enter password for {}:", pass_name);
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read password");
        input.trim().to_string()
    };

    // Encrypt the password using gpg.
    let mut child = Command::new("gpg")
        .args(&[
            "--encrypt",
            "--yes",
            "--batch",
            "--recipient",
            &recipient,
            "--output",
            &passfile,
        ])
        .stdin(Stdio::piped())
        .spawn()
        .expect("Failed to execute gpg command");

    {
        // Write the password to gpg's stdin.
        let child_stdin = child.stdin.as_mut().expect("Failed to open gpg stdin");
        child_stdin
            .write_all(password.as_bytes())
            .expect("Failed to write password to gpg");
    }

    let status = child.wait().expect("Failed to wait on gpg");
    if !status.success() {
        eprintln!("gpg command failed with status: {}", status);
        exit(1);
    }

    println!("Password for '{}' added successfully.", pass_name);
}

fn cmd_init(path: &str) {
    println!("Initialize new password storage at {}", path);

    // Expect the path to be in the format "GPG_ID/subfolder"
    let mut parts = path.splitn(2, '/');
    let gpg_id = parts
        .next()
        .expect("GPG ID must be provided in the init command");
    let subfolder = parts.next().unwrap_or("");

    // Determine the store directory to initialize.
    let store_dir = if subfolder.is_empty() {
        format!("{}", &*PREFIX)
    } else {
        format!("{}/{}", &*PREFIX, subfolder)
    };

    // Create the store directory if it doesn't exist.
    if let Err(e) = std::fs::create_dir_all(&store_dir) {
        eprintln!("Error creating directory {}: {}", store_dir, e);
        std::process::exit(1);
    }

    // Write the .gpg-id file with the provided GPG ID.
    let gpg_id_file = format!("{}/.gpg-id", store_dir);
    if let Err(e) = std::fs::write(&gpg_id_file, gpg_id) {
        eprintln!("Error writing .gpg-id file {}: {}", gpg_id_file, e);
        std::process::exit(1);
    }

    println!(
        "Initialized password store in '{}' with GPG ID: {}",
        store_dir, gpg_id
    );
}

/// Check for sneaky path segments.
fn check_sneaky_paths(paths: Vec<&str>) {
    for path in paths {
        if path.ends_with("/..") || path.starts_with("../") || path.contains("/../") || path == ".."
        {
            panic!("Error: You've attempted to pass a sneaky path to pass. Go home.");
        }
    }
}

fn print_dir_structure(path: &Path, prefix: String) -> std::io::Result<()> {
    if path.is_dir() {
        for entry_result in fs::read_dir(path)? {
            let entry = entry_result?;
            let path = entry.path();
            let filename = path.file_name().unwrap().to_str().unwrap();

            if path.is_dir() {
                println!("{}─ {}", prefix, filename);
                let new_prefix = format!("{}    ", prefix);
                print_dir_structure(&path, new_prefix)?;
            } else {
                if filename.starts_with(".") {
                    continue;
                }
                if filename.ends_with(".gpg") {
                    println!("{}─ {}", prefix, &filename[..filename.len() - 4]);
                } else {
                    println!("{}─ {}", prefix, filename);
                }
            }
        }
    }
    Ok(())
}

fn cmd_show(pass_name: &str) {
    check_sneaky_paths(vec![pass_name]);

    let passfile = format!("{}/{}.gpg", PREFIX.to_string(), pass_name);

    if Path::new(&passfile).exists() {
        let output = Command::new("gpg")
            .arg("-d")
            .arg(&passfile)
            .output()
            .expect("failed to execute gpg");
        let pass = String::from_utf8_lossy(&output.stdout);
        println!("{}", pass);
    } else if Path::new(&PREFIX.to_string()).exists() {
        if pass_name.is_empty() {
            println!("Password Store:");
        } else {
            let trimmed_path = passfile.trim_end_matches('/');
            println!("{}", trimmed_path);
        }
        print_dir_structure(&Path::new(&PREFIX.to_string()), "".to_string()).unwrap();
    } else {
        eprintln!(
            "Error: Password store '{}' does not exist. Try \"pass init\".",
            &*PREFIX
        );
        exit(1);
    }
}

fn cmd_find(pass_names: &str) {
    println!("Searching for passwords that match {}", pass_names);
    // Implement your search logic here...
}

fn cmd_extension(arg: &str) -> Result<(), ()> {
    check_sneaky_paths(vec![arg]);

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Try the user extension first if extensions are enabled.
    if std::env::var("PASSWORD_STORE_ENABLE_EXTENSIONS").ok() == Some("true".to_owned()) {
        if let Some(extensions_dir) = std::env::var("EXTENSIONS").ok() {
            let user_extension = format!("{}/{}.bash", extensions_dir, arg);
            if !user_extension.is_empty()
                && Path::new(&user_extension).is_file()
                && Path::new(&user_extension).is_executable()
            {
                verify_file(&user_extension);
                source_file(&user_extension, &args);
                return Ok(());
            }
        }
    }

    // Otherwise, try the system extension.
    if let Some(system_extension_dir) = std::env::var("SYSTEM_EXTENSION_DIR").ok() {
        let system_extension = format!("{}/{}.bash", system_extension_dir, arg);
        if !system_extension.is_empty()
            && Path::new(&system_extension).is_file()
            && Path::new(&system_extension).is_executable()
        {
            source_file(&system_extension, &args);
            return Ok(());
        }
    }

    Err(())
}

fn cmd_extension_or_show(arg: &str) {
    if cmd_extension(arg).is_err() {
        cmd_show(arg);
    }
}

fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("init", sub_matches)) => {
            let gpg_id = sub_matches
                .get_one::<String>("GPGID")
                .expect("GPGID is required");
            let subfolder = sub_matches
                .get_one::<String>("path")
                .map(String::as_str)
                .unwrap_or("");

            cmd_init(&format!("{}/{}", gpg_id, subfolder));
        }
        Some(("add", sub_matches)) => {
            let pass_name = sub_matches
                .get_one::<String>("PASS_NAME")
                .expect("PASS_NAME is required");
            let maybe_password = sub_matches
                .get_one::<String>("PASSWORD")
                .map(|s| s.as_str());
            cmd_add(pass_name, maybe_password);
        }
        Some(("show", sub_matches)) => {
            let pass_name = sub_matches
                .get_one::<String>("PASS_NAME")
                .map(|s| s.as_str())
                .unwrap_or("");
            cmd_show(pass_name);
        }
        Some(("find", sub_matches)) => {
            let pass_names = sub_matches
                .get_one::<String>("PASS_NAMES")
                .expect("PASS_NAMES is required");
            cmd_find(pass_names);
        }
        Some(("ls", _sub_matches)) => {
            if Path::new(&PREFIX.to_string()).exists() {
                print_dir_structure(&Path::new(&PREFIX.to_string()), "".to_string()).unwrap();
            } else {
                eprintln!(
                    "Password store '{}' does not exist. Try \"pass init\".",
                    &*PREFIX
                );
                exit(1);
            }
        }
        _ => {
            cmd_extension_or_show("");
        }
    }
}
