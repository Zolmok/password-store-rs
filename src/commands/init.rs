use std::fs;
use std::process::{exit, Command};

use crate::integrations::git::git_add_file;
use crate::integrations::gpg::{generate_new_gpg_key, reencrypt_path, sign_file};
use crate::utils::PREFIX;

/// Initializes a new password store by creating a `.gpg-id` file with the specified or generated GPG key.
///
/// This function performs the equivalent of the `pass init` command. It sets up a
/// password store directory (optionally scoped to a subfolder) and configures it
/// with a GPG key ID used for encryption. If no GPG ID is provided or the `--auto`
/// flag is set, a new key is generated interactively using GPG.
///
/// # Arguments
///
/// * `gpg_id_input` - An optional GPG key identifier as a string slice. If `None`
///   or if the key is not found in the keyring, a new key will be generated.
/// * `subfolder` - An optional subfolder under the password store root. If non-empty,
///   the `.gpg-id` will be placed in this subdirectory.
/// * `auto` - A boolean flag indicating whether to force GPG key generation even
///   if a GPG ID is provided.
///
/// # Behavior
///
/// - Ensures the password store directory exists (creates it if needed).
/// - Writes the GPG ID to a `.gpg-id` file inside the store.
/// - Optionally signs the `.gpg-id` file using `PASSWORD_STORE_SIGNING_KEY`.
/// - Re-encrypts the store contents (if applicable).
/// - Stages changes in Git, if Git is enabled.
///
/// # Panics / Exits
///
/// This function terminates the program (`exit(1)`) if:
/// - GPG commands fail to run or return errors.
/// - Filesystem operations fail (creating directories, writing files).
/// - Git operations fail (e.g. staging files).
/// - GPG key generation or fingerprint extraction fails.
///
/// # Example
///
/// ```rust
/// // Initialize with an existing key
/// cmd_init(Some(\"34E8F4A6A3851A5C\"), \"\", false);
///
/// // Initialize with a new key
/// cmd_init(None, \"my/project\", true);
/// ```
pub fn cmd_init(gpg_id_input: Option<&str>, subfolder: &str, auto: bool) {
    println!("Initialize new password storage");

    let store_dir = if subfolder.is_empty() {
        format!("{}", &*PREFIX)
    } else {
        format!("{}/{}", &*PREFIX, subfolder)
    };

    let gpg_id_file = format!("{}/.gpg-id", store_dir);

    let key_id = if auto || gpg_id_input.is_none() {
        println!("No GPG ID provided or auto flag set. Generating a new GPG key...");
        generate_new_gpg_key()
    } else {
        let provided = gpg_id_input.unwrap().trim();
        let output = Command::new("gpg")
            .arg("--list-keys")
            .arg(provided)
            .output()
            .unwrap_or_else(|e| {
                eprintln!("Failed to execute gpg --list-keys: {}", e);
                exit(1);
            });

        if output.stdout.is_empty() {
            println!(
                "Provided key '{}' not found. Generating a new key...",
                provided
            );
            generate_new_gpg_key()
        } else {
            provided.to_string()
        }
    };

    if let Err(e) = fs::create_dir_all(&store_dir) {
        eprintln!("Error creating directory {}: {}", store_dir, e);
        exit(1);
    }

    if let Err(e) = fs::write(&gpg_id_file, format!("{}\n", key_id)) {
        eprintln!("Error writing .gpg-id file {}: {}", gpg_id_file, e);
        exit(1);
    }
    println!(
        "Password store initialized for {}{}",
        key_id,
        if subfolder.is_empty() {
            "".to_string()
        } else {
            format!(" ({})", subfolder)
        }
    );

    if let Err(e) = git_add_file(
        &gpg_id_file,
        &format!(
            "Set GPG id to {}{}",
            key_id,
            if subfolder.is_empty() {
                "".to_string()
            } else {
                format!(" ({})", subfolder)
            }
        ),
    ) {
        eprintln!("Error adding {} to git: {}", gpg_id_file, e);
        exit(1);
    }

    if let Ok(signing_keys) = std::env::var("PASSWORD_STORE_SIGNING_KEY") {
        if !signing_keys.trim().is_empty() {
            if let Err(e) = sign_file(&gpg_id_file) {
                eprintln!("Could not sign .gpg-id: {}", e);
                exit(1);
            }
            println!("Signed .gpg-id file.");
            if let Err(e) = git_add_file(
                &(gpg_id_file.clone() + ".sig"),
                &format!(
                    "Signing new GPG id with {}",
                    signing_keys.replace(" ", ", ")
                ),
            ) {
                eprintln!("Error adding {}.sig to git: {}", gpg_id_file, e);
                exit(1);
            }
        }
    }

    if let Err(e) = reencrypt_path(&store_dir) {
        eprintln!("Error reencrypting path {}: {}", store_dir, e);
        exit(1);
    }

    if let Err(e) = git_add_file(
        &store_dir,
        &format!("Reencrypt password store using new GPG id {}", key_id),
    ) {
        eprintln!("Error adding {} to git: {}", store_dir, e);
        exit(1);
    }
}

