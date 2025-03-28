use crate::utils::PREFIX;

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{exit, Command, Stdio};

/// Adds a new password entry to the password store, similar to pass's cmd_insert.
///
/// This function performs the following steps:
/// 1. Verifies that the password store exists (using the directory defined by [`PREFIX`]).
/// 2. Constructs the file path for the new entry as `<PREFIX>/<pass_name>.gpg`.
/// 3. Reads the GPG recipient from the `.gpg-id` file in the password store.
/// 4. If the entry already exists and force is not enabled, prompts the user to confirm overwrite.
/// 5. Prompts for the password using one of three modes:
///    - **Multiline mode (`multiline == true`)**: Reads until EOF.
///    - **No-echo mode (`echo == false`)**: Reads the password hidden and asks for confirmation.
///    - **Echo mode (`echo == true`)**: Reads the password with echo.
/// 6. Encrypts the password using the GPG command with the specified recipient, writing the encrypted
///    output to the target file.
/// 7. Exits the process with an error if any step fails.
///
/// # Arguments
///
/// * `pass_name` - The name of the password entry. This is used to generate the file name (`.gpg`).
/// * `maybe_password` - An optional password string. If provided, it is used directly.
/// * `multiline` - If true, the input is read as multiline until EOF.
/// * `echo` - If true, the input is read with echo; otherwise (the default), input is hidden.
/// * `force` - If true, any existing entry is overwritten without prompting.
///
/// # Panics
///
/// This function terminates the process if:
/// - The password store does not exist.
/// - Reading the `.gpg-id` file fails.
/// - The GPG command fails to execute or returns a non-success status.
/// - In no-echo mode, the passwords do not match.
///
/// # Examples
///
/// ```rust
/// // Directly add a password (with verification, hidden input) for "example.com".
/// cmd_add("example.com", None, false, false, false);
///
/// // Add a password in echo mode:
/// cmd_add("example.com", None, false, true, false);
///
/// // Add multiline content:
/// cmd_add("example.com", None, true, false, false);
/// ```
pub fn cmd_add(
    pass_name: &str,
    maybe_password: Option<&str>,
    multiline: bool,
    echo: bool,
    force: bool,
) {
    // Ensure the password store exists.
    if !Path::new(&*PREFIX).exists() {
        eprintln!(
            "Error: Password store '{}' does not exist. Try \"pass init\".",
            &*PREFIX
        );
        exit(1);
    }

    let passfile = format!("{}/{}.gpg", &*PREFIX, pass_name);
    let gpg_id_file = format!("{}/.gpg-id", &*PREFIX);

    // Read the GPG recipient from the .gpg-id file.
    let recipient = match fs::read_to_string(&gpg_id_file) {
        Ok(content) => content.trim().to_string(),
        Err(e) => {
            eprintln!(
                "Error reading {}: {}. Is the store initialized?",
                gpg_id_file, e
            );
            exit(1);
        }
    };

    // Check if entry exists and force is not set.
    if !force && Path::new(&passfile).exists() {
        print!("An entry already exists for {}. Overwrite it? [y/N]: ", pass_name);
        io::stdout().flush().unwrap();
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err() {
            eprintln!("Failed to read confirmation.");
            exit(1);
        }
        if !answer.trim().to_lowercase().starts_with('y') {
            println!("Aborting.");
            exit(0);
        }
    }

    // Create parent directory if necessary.
    if let Some(parent) = Path::new(&passfile).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("Error creating directory {}: {}", parent.display(), e);
            exit(1);
        }
    }

    // Determine the password.
    let password: String = if let Some(p) = maybe_password {
        p.to_string()
    } else if multiline {
        println!("Enter contents of {} and press Ctrl+D when finished:", pass_name);
        let mut buffer = String::new();
        match io::stdin().read_to_string(&mut buffer) {
            Ok(_) => buffer.trim().to_string(),
            Err(e) => {
                eprintln!("Failed to read multiline input: {}", e);
                exit(1);
            }
        }
    } else if !echo {
        // Use hidden input with confirmation.
        let password = rpassword::prompt_password(&format!("Enter password for {}: ", pass_name))
            .unwrap_or_else(|e| {
                eprintln!("Failed to read password: {}", e);
                exit(1);
            });
        let password_again = rpassword::prompt_password(&format!("Retype password for {}: ", pass_name))
            .unwrap_or_else(|e| {
                eprintln!("Failed to read password confirmation: {}", e);
                exit(1);
            });

        if password != password_again {
            eprintln!("Error: the entered passwords do not match.");
            exit(1);
        }
        password
    } else {
        // Echo mode: read normally.
        print!("Enter password for {}: ", pass_name);
        io::stdout().flush().unwrap();
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(_) => line.trim().to_string(),
            Err(e) => {
                eprintln!("Failed to read password: {}", e);
                exit(1);
            }
        }
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
        .unwrap_or_else(|e| {
            eprintln!("Failed to execute gpg command: {}", e);
            exit(1);
        });

    {
        let child_stdin = child.stdin.as_mut().unwrap_or_else(|| {
            eprintln!("Failed to open gpg stdin");
            exit(1);
        });
        if let Err(e) = child_stdin.write_all(password.as_bytes()) {
            eprintln!("Failed to write password to gpg: {}", e);
            exit(1);
        }
    }

    let status = child.wait().unwrap_or_else(|e| {
        eprintln!("Failed to wait on gpg: {}", e);
        exit(1);
    });
    if !status.success() {
        eprintln!("gpg command failed with status: {}", status);
        exit(1);
    }

    println!("Password for '{}' added successfully.", pass_name);

    // git_add_file(&passfile, &format!("Add given password for {} to store.", pass_name))
}
