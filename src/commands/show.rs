use crate::utils::{check_sneaky_paths, print_dir_structure, PREFIX};
use std::path::Path;
use std::process::{exit, Command};

/// Displays a password entry or the password store structure.
///
/// This function handles the "show" command for the password store application. It performs the following:
///
/// 1. Validates the provided `pass_name` by checking for any potentially dangerous path segments using
///    [`check_sneaky_paths`].
/// 2. Constructs the expected file path for the password entry as `<PREFIX>/<pass_name>.gpg`.
/// 3. If the file exists, it decrypts the password using the GPG command (`gpg -d`) and prints the result.
/// 4. If the file does not exist:
///    - If `pass_name` is empty, it prints the entire password store directory structure using
///      [`print_dir_structure`].
///    - Otherwise, it prints an error message indicating that the password entry is not found and exits.
///
/// # Arguments
///
/// * `pass_name` - A string slice that specifies the name of the password entry to display. When empty,
///   the function prints the directory structure of the password store.
///
/// # Panics
///
/// The function will terminate the process if:
/// - The GPG decryption command fails.
/// - The password store directory does not exist when attempting to list its structure.
/// - The `pass_name` contains suspicious path segments (as determined by [`check_sneaky_paths`]).
///
/// # Examples
///
/// ```rust
/// // To display the decrypted password for "example.com":
/// cmd_show("example.com");
///
/// // To list the password store structure:
/// cmd_show("");
/// ```
pub fn cmd_show(pass_name: &str) {
    check_sneaky_paths(vec![pass_name]);

    let passfile = format!("{}/{}.gpg", &*PREFIX, pass_name);

    if Path::new(&passfile).exists() {
        let output = Command::new("gpg")
            .arg("-d")
            .arg(&passfile)
            .output()
            .expect("failed to execute gpg");
        let pass = String::from_utf8_lossy(&output.stdout);
        println!("{}", pass);
    } else if Path::new(&*PREFIX).exists() {
        if pass_name.is_empty() {
            println!("Password Store");
        } else {
            let trimmed_path = passfile.trim_end_matches('/');
            println!("{}", trimmed_path);
        }
        print_dir_structure(&Path::new(&*PREFIX), "".to_string()).unwrap();
    } else {
        eprintln!(
            "Error: Password store '{}' does not exist. Try \"pass init\".",
            &*PREFIX
        );
        exit(1);
    }
}
