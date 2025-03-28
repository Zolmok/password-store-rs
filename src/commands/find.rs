use crate::utils::PREFIX;
use regex::Regex;
use std::process::{exit, Command};

/// Searches for password entries in the password store that match the given search terms.
///
/// This function implements the "find" command by replicating the behavior of the original pass
/// script. It performs the following steps:
///
/// 1. Verifies that at least one search term is provided; if not, it prints a usage message and exits.
/// 2. Prints the search terms being used.
/// 3. Constructs a pattern string for use with the `tree` command. The pattern is built by wrapping each
///    search term with asterisks (`*`), and joining them with a vertical bar (`|`) to allow matching any of the terms.
///    For example, if the search terms are "email" and "bank", the pattern becomes "*email*|*bank*".
/// 4. Executes the external `tree` command with options to display the directory structure of the password store
///    (defined by [`PREFIX`]) filtered by the constructed pattern. The command is run with the following options:
///    - `-N -C -l --noreport`: to produce a colored, indented tree listing without a summary report.
///    - `--prune`: to omit directories that do not contain matching entries.
///    - `--matchdirs`: to match directory names as well.
///    - `--ignore-case`: for case-insensitive matching.
/// 5. Processes the output of the `tree` command by skipping the first line (header) and removing any occurrences of
///    the `.gpg` extension from file names using a regular expression.
/// 6. Prints the resulting filtered tree view to standard output.
///
/// # Arguments
///
/// * `pass_names` - A string slice containing one or more search terms (typically separated by whitespace).
///
/// # Panics
///
/// The function will terminate the process if:
/// - No search terms are provided.
/// - The external `tree` command fails to execute.
/// - The output from the `tree` command cannot be properly processed.
///
/// # Examples
///
/// ```rust
/// // Search for password entries that contain "email" or "bank"
/// cmd_find("email bank");
/// ```
pub fn cmd_find(pass_names: &str) {
    // Split the search terms by whitespace.
    let terms: Vec<&str> = pass_names.split_whitespace().collect();

    if terms.is_empty() {
        eprintln!("Usage: pass find pass-names...");
        exit(1);
    }

    // Print the search terms (separated by commas).
    println!("Search Terms: {}", terms.join(", "));

    // Construct the pattern string.
    // For example, if terms are ["email", "bank"], the pattern becomes "*email*|*bank*".
    let pattern = format!("*{}*", terms.join("*|*"));

    // Execute the `tree` command with the specified options.
    let output = Command::new("tree")
        .args(&[
            "-N",
            "-C",
            "-l",
            "--noreport",
            "-P",
            &pattern,
            "--prune",
            "--matchdirs",
            "--ignore-case",
            &*PREFIX,
        ])
        .output()
        .expect("Failed to execute tree command");

    if !output.status.success() {
        eprintln!("Error executing tree command.");
        exit(1);
    }

    // Convert the output to a string and split it into lines.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    // Skip the first line (header) if it exists.
    let processed_lines = if lines.len() > 1 {
        &lines[1..]
    } else {
        &lines[..]
    };

    // Compile a regex to remove ".gpg" (and optional color escape sequences) from file names.
    let re = Regex::new(r"\.gpg(\x1B\[[0-9]+m)?( ->|$)").unwrap();

    // Process each line and print the result.
    for line in processed_lines {
        let processed_line = re.replace_all(line, "$1$2");

        println!("{}", processed_line);
    }
}
