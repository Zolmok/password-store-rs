use crate::utils::PREFIX;
use std::fs;
use std::process::exit;

/// Initializes the password store directory and configures it for encryption.
///
/// This function sets up a new password store by performing the following steps:
///
/// 1. Parses the input `path` string, which should be in the format `"GPG_ID/subfolder"`.
///    - The `GPG_ID` part is mandatory and specifies the GPG key identifier.
///    - The `subfolder` part is optional. If omitted, the store will be initialized
///      in the default location specified by [`PREFIX`].
/// 2. Determines the directory path to create for the password store based on the provided subfolder.
/// 3. Creates the directory (and any necessary parent directories) for the password store.
/// 4. Writes a `.gpg-id` file in the store directory containing the GPG key identifier,
///    which is used by GPG for encrypting and decrypting password files.
///
/// # Arguments
///
/// * `path` - A string slice representing the initialization parameters in the format `"GPG_ID/subfolder"`.
///            The `subfolder` is optional; if omitted, the store will be initialized at the default path.
///
/// # Panics
///
/// The function will terminate the process if:
/// - The provided `GPG_ID` is missing.
/// - Directory creation fails.
/// - Writing the `.gpg-id` file fails.
///
/// # Examples
///
/// ```rust
/// // Initialize the password store with GPG ID "123" in the subfolder "sub-folder-name"
/// cmd_init("123/sub-folder-name");
///
/// // Alternatively, initialize the store with GPG ID "123" at the default location
/// cmd_init("123");
/// ```
pub fn cmd_init(path: &str) {
    println!("Initialize new password storage at {}", path);

    // Parse the input; if the path string is "GPG_ID/subfolder", split it.
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

    // Create the directory structure.
    if let Err(e) = fs::create_dir_all(&store_dir) {
        eprintln!("Error creating directory {}: {}", store_dir, e);
        exit(1);
    }

    // Write the .gpg-id file containing the GPG recipient.
    let gpg_id_file = format!("{}/.gpg-id", store_dir);
    if let Err(e) = fs::write(&gpg_id_file, gpg_id) {
        eprintln!("Error writing .gpg-id file {}: {}", gpg_id_file, e);
        exit(1);
    }

    println!(
        "Initialized password store in '{}' with GPG ID: {}",
        store_dir, gpg_id
    );
}
