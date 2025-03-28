use std::fs;
use std::path::Path;
use std::process::exit;

use crate::integrations::git::{git_add_file, git_remove_file};
use crate::integrations::gpg::{reencrypt_path, sign_file};
use crate::utils::PREFIX;

/// Initializes (or deinitializes) the password store with a new GPG ID.
///
/// This function replicates the behavior of the original pass script's `cmd_init` command. It performs
/// the following steps:
///
/// 1. Parses the input string, which is expected to be in the format `"GPG_ID[/subfolder]"`.
///    - The first part is the GPG key identifier. If it is an empty string, the function will attempt to
///      deinitialize (remove) the existing GPG configuration.
///    - The optional subfolder specifies a subdirectory under the password store.
/// 2. Constructs the target store directory as `<PREFIX>[/subfolder]`.
/// 3. If deinitializing (i.e. the provided GPG ID is empty):
///    - Verifies that the `.gpg-id` file exists in the store directory and then removes it.
///    - Attempts to remove the store directory if it becomes empty.
/// 4. Otherwise (initializing):
///    - Creates the store directory (if it does not already exist).
///    - Writes the provided GPG ID(s) (followed by a newline) to a `.gpg-id` file within the store directory.
///    - If the environment variable `PASSWORD_STORE_SIGNING_KEY` is set, the function attempts to sign the
///      `.gpg-id` file using a signing function.
///    - (Optionally) The function would add the file(s) to Git.
/// 5. In all cases, the function calls functions to reencrypt the store and add changes to Git.
///
/// # Arguments
///
/// * `path` - A string slice in the format `"GPG_ID[/subfolder]"`. An empty GPG_ID indicates that the
///            existing configuration should be deinitialized.
///
/// # Panics
///
/// The function will terminate the process if:
/// - The directory creation or file operations fail.
/// - The deinitialization branch is invoked but no `.gpg-id` file exists.
/// - Signing is enabled but signing fails.
/// - Reencrypting or adding files to Git fails.
///
/// # Examples
///
/// ```rust
/// // To initialize the store with GPG ID "123" in the "socketwiz" subfolder:
/// cmd_init("123/socketwiz");
///
/// // To initialize the store with GPG ID "123" at the default location:
/// cmd_init("123");
///
/// // To deinitialize (remove) the current GPG ID (assuming the optional subfolder is provided as needed):
/// cmd_init("/socketwiz");
/// ```
pub fn cmd_init(path: &str) {
    println!("Initialize new password storage at {}", path);

    // Split the input into GPG ID and optional subfolder.
    let mut parts = path.splitn(2, '/');
    let gpg_id_input = parts.next().unwrap_or(""); // may be empty for deinit
    let subfolder = parts.next().unwrap_or("");

    // Determine the target store directory.
    let store_dir = if subfolder.is_empty() {
        format!("{}", &*PREFIX)
    } else {
        format!("{}/{}", &*PREFIX, subfolder)
    };

    // Build the full path to the .gpg-id file.
    let gpg_id_file = format!("{}/.gpg-id", store_dir);

    // If the provided GPG ID is empty, we are in deinitialization mode.
    if gpg_id_input.trim().is_empty() {
        if !Path::new(&gpg_id_file).exists() {
            eprintln!(
                "Error: {} does not exist and so cannot be removed.",
                gpg_id_file
            );
            exit(1);
        }

        if let Err(e) = fs::remove_file(&gpg_id_file) {
            eprintln!("Error removing {}: {}", gpg_id_file, e);
            exit(1);
        }

        println!("Removed {}", gpg_id_file);

        git_remove_file(
            &gpg_id_file,
            &format!(
                "Deinitialize {}{}",
                gpg_id_file,
                if subfolder.is_empty() {
                    "".to_string()
                } else {
                    format!(" ({})", subfolder)
                }
            ),
        );

        // Attempt to remove the directory if empty.
        if let Err(e) = fs::remove_dir(&store_dir) {
            eprintln!("Warning: Could not remove directory {}: {}", store_dir, e);
        }
    } else {
        // Initialization branch.
        if let Err(e) = fs::create_dir_all(&store_dir) {
            eprintln!("Error creating directory {}: {}", store_dir, e);
            exit(1);
        }

        // Write the provided GPG ID(s) to the .gpg-id file.
        if let Err(e) = fs::write(&gpg_id_file, format!("{}\n", gpg_id_input)) {
            eprintln!("Error writing .gpg-id file {}: {}", gpg_id_file, e);
            exit(1);
        }
        println!(
            "Password store initialized for {}{}",
            gpg_id_input,
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
                gpg_id_input,
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

        // If a signing key is set, sign the .gpg-id file.
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
    }

    if let Err(e) = reencrypt_path(&store_dir) {
        eprintln!("Error reencrypting path {}: {}", store_dir, e);
        exit(1);
    }

    if let Err(e) = git_add_file(
        &store_dir,
        &format!("Reencrypt password store using new GPG id {}", gpg_id_input),
    ) {
        eprintln!("Error adding {} to git: {}", store_dir, e);
        exit(1);
    }
}
