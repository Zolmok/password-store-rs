mod commands;
mod utils;

use clap::{arg, Command as ClapCommand};

/// Constructs the command-line interface (CLI) for the password store application.
///
/// This function builds and returns a [`clap::Command`] that defines the structure
/// of the CLI for the password manager. The CLI includes the following subcommands:
///
/// - **init**: Initializes a new password store by specifying a GPG key identifier and an optional subfolder.
/// - **add**: Adds a new password entry to the store. The password can be provided directly as an argument,
///   or, if omitted, the user will be prompted to enter it interactively.
/// - **show**: Displays an existing password entry (and can optionally place it on the clipboard).
/// - **find**: Searches for passwords matching a specified query.
///
/// # Examples
///
/// ```rust
/// let app = cli();
/// let matches = app.get_matches();
/// // Dispatch to appropriate command based on the matches...
/// ```
///
/// # Returns
///
/// A [`clap::Command`] that is pre-configured with the application's subcommands and options.
fn cli() -> ClapCommand {
    ClapCommand::new("pass-rs")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("A password manager")
        .subcommand(
            ClapCommand::new("init")
                .about("Initialize new password storage and use gpg-id for encryption")
                .arg(arg!(<GPGID> "Specifies a GPG key identifier").value_name("gpg-id"))
                // Making the path optional:
                .arg(arg!(-p --path [subfolder] "Specifies an optional subfolder").id("subfolder")),
        )
        .subcommand(
            ClapCommand::new("add")
                .about("Add a new password")
                .arg(arg!(<PASS_NAME> "The name of the password entry").value_name("pass-name"))
                .arg(arg!([PASSWORD] "The password to store (if not provided, you will be prompted)").value_name("password"))
        )
        .subcommand(
            ClapCommand::new("show")
                .about("Show an existing password")
                .arg(arg!(<PASS_NAME> "Specifies a pass-name").value_name("pass-name").required(false))
                .arg(arg!(-c --clip "Put the password on the clipboard (clears in $CLIP_TIME seconds)"))
        )
        .subcommand(
            ClapCommand::new("find")
                .about("List passwords that match a pass-name.")
                .arg(arg!(<PASS_NAMES> "Specifies a pass-name").value_name("pass-names"))
        )
}

/// The entry point for the password store application.
///
/// This function performs the following steps:
/// 1. Constructs the command-line interface (CLI) by calling the [`cli`] function.
/// 2. Parses the command-line arguments using Clap.
/// 3. Dispatches to the appropriate command handler based on the provided subcommand.
///    - **init**: Initializes a new password store.
///    - **add**: Adds a new password entry to the store.
///    - **show**: Displays an existing password entry (and optionally places it on the clipboard).
///    - **find**: Searches for password entries matching a query.
/// 4. If no valid subcommand is provided, it prints the help message to guide the user.
///
/// # Example
///
/// To initialize a new password store with a GPG ID of "123" and an optional subfolder "socketwiz", run:
///
/// ```bash
/// cargo run -- init 123 -p socketwiz
/// ```
///
/// If no subcommand is provided, the application will print the help message.
fn main() {
    let mut app = cli();
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some(("init", sub_matches)) => {
            let gpg_id = sub_matches
                .get_one::<String>("GPGID")
                .expect("GPGID is required");
            let subfolder = sub_matches
                .get_one::<String>("subfolder")
                .map(String::as_str)
                .unwrap_or("");
            commands::init::cmd_init(&format!("{}/{}", gpg_id, subfolder));
        }
        Some(("add", sub_matches)) => {
            let pass_name = sub_matches
                .get_one::<String>("PASS_NAME")
                .expect("PASS_NAME is required");
            let maybe_password = sub_matches
                .get_one::<String>("password")
                .map(|s| s.as_str());
            commands::add::cmd_add(pass_name, maybe_password);
        }
        Some(("show", sub_matches)) => {
            let pass_name = sub_matches
                .get_one::<String>("PASS_NAME")
                .map(String::as_str)
                .unwrap_or("");
            commands::show::cmd_show(pass_name);
        }
        Some(("find", sub_matches)) => {
            let pass_names = sub_matches
                .get_one::<String>("PASS_NAMES")
                .expect("PASS_NAMES is required");
            commands::find::cmd_find(pass_names);
        }
        _ => {
            // Print help if no valid subcommand is provided.
            app.print_help().expect("Failed to print help");
            println!();
        }
    }
}



