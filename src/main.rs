mod commands;
mod integrations;
mod utils;

use clap::{arg, Arg, ArgAction, Command as ClapCommand};

/// Constructs the command-line interface (CLI) for the password store application.
///
/// This function builds and returns a [`clap::Command`] that defines the structure
/// of the CLI for the password manager. The CLI includes the following subcommands:
///
/// - **init**: Initializes a new password store by specifying a GPG key identifier and an optional subfolder.
/// - **add**: Adds a new password entry to the store. The password can be provided directly as an argument,
///   or, if omitted, the user will be prompted to enter it interactively. In addition, the "add" subcommand
///   supports extra options:
///     - `--multiline` (`-m`): Read the password input in multiline mode (until EOF).
///     - `--echo` (`-e`): Read the password with echo enabled (i.e. visible input).
///     - `--force` (`-f`): Force overwrite an existing entry without prompting for confirmation.
/// - **show**: Displays an existing password entry (and can optionally place it on the clipboard).
/// - **find**: Searches for passwords matching a specified query (pass-name).
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
        .author("Ricky Nelson <rickyn@socketwiz.com>")
        .about("A GPG-based password manager inspired by `pass`, built in Rust")
        .subcommand(
            ClapCommand::new("init")
                .about("Initialize new password storage and use gpg-id for encryption")
                .arg(arg!([GPGID] "Specifies a GPG key identifier").value_name("gpg-id"))
                .arg(arg!(-p --path [subfolder] "Specifies an optional subfolder").id("subfolder"))
                // Add a flag to force auto-generation even if a key was provided.
                .arg(arg!(-a --auto "Automatically generate a new GPG key").action(ArgAction::SetTrue)),
        )
        .subcommand(
            ClapCommand::new("add")
                .about("Add a new password entry")
                .arg(arg!(<PASS_NAME> "The name of the password entry").value_name("pass-name"))
                .arg(arg!([PASSWORD] "The password to store (if not provided, you will be prompted)").value_name("PASSWORD"))
                .arg(
                    Arg::new("multiline")
                        .short('m')
                        .long("multiline")
                        .help("Read password in multiline mode")
                        .action(ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("echo")
                        .short('e')
                        .long("echo")
                        .help("Read password with echo enabled")
                        .action(ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("force")
                        .short('f')
                        .long("force")
                        .help("Force overwrite an existing entry")
                        .action(ArgAction::SetTrue)
                ),
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
/// 3. Dispatches to the appropriate command handler based on the provided subcommand:
///    - **init**: Initializes a new password store.
///    - **add**: Adds a new password entry to the store.
///    - **show**: Displays an existing password entry (and optionally places it on the clipboard).
///    - **find**: Searches for password entries matching a query.
/// 4. If no valid subcommand is provided, it calls `cmd_show` to display the entire password store.
///
/// # Example
///
/// To initialize a new password store with a GPG ID of "123" and an optional subfolder "socketwiz", run:
///
/// ```bash
/// cargo run -- init 123 -p socketwiz
/// ```
///
/// If no subcommand is provided, the application will display the password store.
fn main() {
    let app = cli();
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some(("init", sub_matches)) => {
            let gpg_id_opt = sub_matches.get_one::<String>("GPGID").map(String::as_str);
            let subfolder = sub_matches
                .get_one::<String>("subfolder")
                .map(String::as_str)
                .unwrap_or("");
            let auto = sub_matches.get_flag("auto");

            commands::init::cmd_init(gpg_id_opt, subfolder, auto);
        }
        Some(("add", sub_matches)) => {
            let pass_name = sub_matches
                .get_one::<String>("PASS_NAME")
                .expect("PASS_NAME is required");
            let maybe_password = sub_matches
                .get_one::<String>("PASSWORD")
                .map(|s| s.as_str());
            let multiline = sub_matches.get_flag("multiline");
            let echo = sub_matches.get_flag("echo");
            let force = sub_matches.get_flag("force");

            commands::add::cmd_add(pass_name, maybe_password, multiline, echo, force);
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
            // When no subcommand is provided, display the password store.
            commands::show::cmd_show("");
        }
    }
}
