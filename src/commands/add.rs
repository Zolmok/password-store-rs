use crate::utils::PREFIX;
use std::io::{self, Write};
use std::path::Path;
use std::process::{exit, Command, Stdio};

/// Adds a new password entry to the password store.
///
/// This function creates a new password entry by encrypting the provided password
/// using GPG and storing it in the password store directory. It performs the following steps:
///
/// 1. Verifies that the password store exists (using the directory defined by [`PREFIX`]).
/// 2. Constructs the file path for the new entry as `<PREFIX>/<pass_name>.gpg`.
/// 3. Reads the GPG recipient from the `.gpg-id` file in the password store.
/// 4. Retrieves the password either from the provided `maybe_password` argument or,
///    if not provided, prompts the user to enter it interactively.
/// 5. Encrypts the password using the GPG command with the specified recipient,
///    writing the encrypted output to the target file.
/// 6. Exits the process with an error if any step fails.
///
/// # Arguments
///
/// * `pass_name` - The name of the password entry. This name is used to generate the file name
///   (with a `.gpg` extension) where the encrypted password will be stored.
/// * `maybe_password` - An optional password string. If `None`, the function prompts the user
///   to enter the password interactively.
///
/// # Panics
///
/// This function will terminate the process if:
/// - The password store does not exist.
/// - Reading the `.gpg-id` file fails (indicating that the store may not have been initialized).
/// - The GPG command fails to execute or returns a non-success status.
///
/// # Examples
///
/// ```rust
/// // Directly add a password by providing it as an argument.
/// cmd_add("example.com", Some("supersecret"));
///
/// // Alternatively, add a password interactively by omitting the password argument.
/// cmd_add("example.com", None);
/// ```
pub fn cmd_add(pass_name: &str, maybe_password: Option<&str>) {
    // Ensure the password store exists.
    if !Path::new(&*PREFIX).exists() {
        eprintln!(
            "Error: Password store '{}' does not exist. Try \"pass init\".",
            &*PREFIX
        );
        exit(1);
    }

    let passfile = format!("{}/{}.gpg", &*PREFIX, pass_name);

    // Read the GPG recipient from the .gpg-id file.
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

    // Get the password from argument or prompt.
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
