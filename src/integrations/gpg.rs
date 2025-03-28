use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::process::{exit, Command, Stdio};

/// Signs the specified file using GPG with a detached signature.
///
/// This function attempts to sign the file located at `file_path` by invoking GPG with the
/// `--detach-sign` option. It incorporates additional configuration as follows:
///
/// - Additional GPG options are taken from the `GPG_OPTS` environment variable (if set).
/// - Default signing keys are read from the `PASSWORD_STORE_SIGNING_KEY` environment variable (if set),
///   with each key provided via a `--default-key` argument.
/// - The GPG executable is determined by the `GPG` environment variable, defaulting to `"gpg"` if not set.
///
/// # Arguments
///
/// * `file_path` - The path to the file that should be signed.
///
/// # Returns
///
/// * `Ok(())` if the signing process completes successfully.
/// * `Err(String)` if there is an error invoking GPG or if GPG returns a non-success exit status.
///
/// # Examples
///
/// ```rust
/// // Attempt to sign a file located at "/path/to/.gpg-id"
/// match sign_file("/path/to/.gpg-id") {
///     Ok(()) => println!("File signed successfully."),
///     Err(e) => eprintln!("Signing failed: {}", e),
/// }
/// ```
pub fn sign_file(file_path: &str) -> Result<(), String> {
    // Use the GPG environment variable if set, otherwise default to "gpg"
    let gpg_executable = std::env::var("GPG").unwrap_or_else(|_| "gpg".to_string());

    // Retrieve additional GPG options from the GPG_OPTS environment variable.
    let gpg_opts = std::env::var("GPG_OPTS").unwrap_or_default();
    let gpg_opts_args: Vec<&str> = gpg_opts.split_whitespace().collect();

    // Prepare signing key arguments from PASSWORD_STORE_SIGNING_KEY.
    let mut signing_args: Vec<String> = Vec::new();
    if let Ok(signing_keys) = std::env::var("PASSWORD_STORE_SIGNING_KEY") {
        if !signing_keys.trim().is_empty() {
            for key in signing_keys.split_whitespace() {
                signing_args.push("--default-key".to_string());
                signing_args.push(key.to_string());
            }
        }
    }

    // Build the GPG command.
    let mut cmd = std::process::Command::new(&gpg_executable);

    // Add GPG options.
    for arg in gpg_opts_args {
        cmd.arg(arg);
    }
    // Add signing key options.
    for arg in signing_args {
        cmd.arg(arg);
    }
    // Add the --detach-sign flag and the file to sign.
    cmd.arg("--detach-sign").arg(file_path);

    // Execute the command and capture its output.
    let output = match cmd
        .output()
        .map_err(|e| format!("Failed to execute {}: {}", gpg_executable, e))
    {
        Ok(o) => o,
        Err(err) => return Err(err),
    };

    if !output.status.success() {
        return Err(format!(
            "GPG exited with status {} when signing file {}",
            output.status, file_path
        ));
    }

    Ok(())
}

/// Reencrypts all `.gpg` files in the specified directory tree using the recipient defined in the `.gpg-id` file.
///
/// This function performs the following steps:
///
/// 1. Verifies that `path` is a directory and reads the recipient from the `.gpg-id` file located in that directory.
/// 2. Recursively walks through the directory tree rooted at `path`.
/// 3. For each file that ends with the `.gpg` extension:
///    - Decrypts the file using `gpg -d`.
///    - Re-encrypts the decrypted content using `gpg --encrypt --yes --batch --recipient <recipient> --output <file>`
///      so that the file is re-encrypted with the current GPG configuration.
/// 4. Returns an `Ok(())` on success, or an `Err(String)` containing an error message if any step fails.
///
/// # Arguments
///
/// * `path` - A string slice representing the root directory of the password store to reencrypt.
///
/// # Returns
///
/// * `Ok(())` if all files are successfully reencrypted.
/// * `Err(String)` if there is an error reading directories, files, or if any GPG command fails.
///
/// # Examples
///
/// ```rust
/// match reencrypt_path("/path/to/password-store") {
///     Ok(()) => println!("Reencryption successful."),
///     Err(e) => eprintln!("Reencryption failed: {}", e),
/// }
/// ```
pub fn reencrypt_path(path: &str) -> Result<(), String> {
    let root = Path::new(path);
    if !root.is_dir() {
        return Err(format!("Provided path {} is not a directory", path));
    }

    // Read the recipient from the .gpg-id file in the root directory.
    let gpg_id_path = root.join(".gpg-id");
    let recipient = match std::fs::read_to_string(&gpg_id_path) {
        Ok(content) => content.trim().to_string(),
        Err(e) => return Err(format!("Failed to read {}: {}", gpg_id_path.display(), e)),
    };
    if recipient.is_empty() {
        return Err("No recipient found in .gpg-id".to_string());
    }

    // Recursively process the directory.
    fn reencrypt_dir(dir: &Path, recipient: &str) -> Result<(), String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => return Err(format!("Failed to read directory {}: {}", dir.display(), e)),
        };

        for entry in entries {
            let entry = match entry {
                Ok(ent) => ent,
                Err(e) => return Err(format!("Failed to read directory entry: {}", e)),
            };
            let path = entry.path();

            if path.is_dir() {
                if let Err(e) = reencrypt_dir(&path, recipient) {
                    return Err(e);
                }
            } else {
                if let Some(ext) = path.extension() {
                    if ext == "gpg" {
                        // Decrypt the file.
                        let output = match Command::new("gpg")
                            .arg("-d")
                            .arg(
                                path.to_str()
                                    .ok_or_else(|| format!("Invalid path: {}", path.display()))
                                    .unwrap(),
                            )
                            .output()
                        {
                            Ok(out) => out,
                            Err(e) => {
                                return Err(format!(
                                    "Failed to execute gpg for {}: {}",
                                    path.display(),
                                    e
                                ))
                            }
                        };
                        if !output.status.success() {
                            return Err(format!(
                                "GPG decryption failed for {} with status {}",
                                path.display(),
                                output.status
                            ));
                        }
                        let decrypted = output.stdout;

                        // Re-encrypt the content using the provided recipient.
                        // First, spawn the GPG process for encryption.
                        let file_str = match path.to_str() {
                            Some(s) => s,
                            None => return Err(format!("Invalid path: {}", path.display())),
                        };
                        let mut child = match Command::new("gpg")
                            .args(&[
                                "--encrypt",
                                "--yes",
                                "--batch",
                                "--recipient",
                                recipient,
                                "--output",
                                file_str,
                            ])
                            .stdin(Stdio::piped())
                            .spawn()
                        {
                            Ok(child) => child,
                            Err(e) => {
                                return Err(format!(
                                    "Failed to reencrypt {}: {}",
                                    path.display(),
                                    e
                                ))
                            }
                        };

                        // Write the decrypted content to the child process's stdin.
                        let child_stdin = match child.stdin.as_mut() {
                            Some(stdin) => stdin,
                            None => return Err("Failed to open gpg stdin".to_string()),
                        };

                        if let Err(e) = child_stdin.write_all(&decrypted) {
                            return Err(format!(
                                "Failed to write to gpg stdin for {}: {}",
                                path.display(),
                                e
                            ));
                        }

                        // Wait for the encryption process to finish.
                        let status = match child.wait() {
                            Ok(status) => status,
                            Err(e) => {
                                return Err(format!(
                                    "Failed to wait on gpg for {}: {}",
                                    path.display(),
                                    e
                                ))
                            }
                        };
                        if !status.success() {
                            return Err(format!(
                                "GPG re-encryption failed for {} with status {}",
                                path.display(),
                                status
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    reencrypt_dir(root, &recipient)
}

/// Returns a set of all GPG key fingerprints currently available in the keyring.
///
/// This function runs `gpg --list-keys --with-colons` and parses its output
/// to extract all fingerprint (`fpr`) entries. It collects fingerprints from
/// both primary keys and subkeys.
///
/// # Returns
///
/// A `HashSet<String>` containing the fingerprints of all public keys (both
/// primary and subkeys) found in the GPG keyring.
///
/// # Panics
///
/// This function will panic if the `gpg` command fails to execute successfully.
///
/// # Notes
///
/// - Fingerprints are returned as-is in the order parsed from the output.
/// - Duplicate entries are automatically de-duplicated by the `HashSet`.
/// - If you want only primary key fingerprints, use [`get_primary_fingerprint`] instead.
///
/// # Example
///
/// ```rust
/// let fingerprints = list_key_fingerprints();
/// for fpr in &fingerprints {
///     println!(\"Key: {}\", fpr);
/// }
/// ```
pub fn list_key_fingerprints() -> HashSet<String> {
    let output = Command::new("gpg")
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("Failed to list GPG keys");

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter_map(|line| {
            if line.starts_with("fpr:") {
                line.split(':').nth(9).map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Returns the fingerprint of the most recently listed primary GPG key (if any).
///
/// This function parses the output of `gpg --list-keys --with-colons` to find the
/// fingerprint (`fpr`) line immediately following a `pub` (public key) line.
/// It assumes that the GPG keyring is in a consistent format and that the fingerprint
/// for each primary key directly follows its `pub:` entry.
///
/// # Returns
///
/// - `Some(String)` containing the fingerprint of the first encountered primary key.
/// - `None` if no valid primary key fingerprint can be found.
///
/// # Panics
///
/// This function panics if the `gpg` command fails to execute.
///
/// # Notes
///
/// - This only returns the **first** primary key found in the output.
/// - It ignores subkey (`sub:`) entries and their fingerprints.
/// - Suitable for use cases where a single default or most recently generated key is expected.
///
/// # Example
///
/// ```rust
/// if let Some(fpr) = get_primary_fingerprint() {
///     println!(\"Primary key fingerprint: {}\", fpr);
/// } else {
///     println!(\"No primary GPG key found.\");
/// }
/// ```
pub fn get_primary_fingerprint() -> Option<String> {
    let output = Command::new("gpg")
        .args(["--list-keys", "--with-colons"])
        .output()
        .expect("Failed to list GPG keys");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_pub = false;

    for line in stdout.lines() {
        if line.starts_with("pub:") {
            in_pub = true;
        } else if in_pub && line.starts_with("fpr:") {
            return line.split(':').nth(9).map(|s| s.to_string());
        }
    }

    None
}

/// Generates a new GPG key using the interactive `gpg --full-gen-key` command
/// and returns the fingerprint of the newly created **primary** key.
///
/// This function invokes GPG in interactive mode to create a new key pair.
/// After generation, it retrieves and returns the fingerprint of the primary
/// key (not the subkey), which is typically used for signing and identifying
/// the key.
///
/// # Returns
///
/// A `String` representing the fingerprint of the newly generated primary key.
///
/// # Panics
///
/// This function will terminate the program (`exit(1)`) if:
/// - The `gpg` command fails to execute.
/// - The user cancels or fails to complete the key generation.
/// - The primary key fingerprint cannot be extracted after key creation.
///
/// # Notes
///
/// - The GPG interface is interactive and requires user input.
/// - It is assumed that the key created is the most recent one in the keyring.
///
/// # Example
///
/// ```rust
/// let new_fpr = generate_new_gpg_key();
/// println!(\"New GPG key fingerprint: {}\", new_fpr);
/// ```
pub fn generate_new_gpg_key() -> String {
    let status = Command::new("gpg")
        .arg("--full-gen-key")
        .status()
        .unwrap_or_else(|e| {
            eprintln!("Failed to execute gpg --full-gen-key: {}", e);
            exit(1);
        });

    if !status.success() {
        eprintln!("Failed to generate a new GPG key.");
        exit(1);
    }

    let fingerprint = get_primary_fingerprint().unwrap_or_else(|| {
        eprintln!("Failed to extract primary fingerprint from generated key.");
        exit(1);
    });

    fingerprint
}
