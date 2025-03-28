use once_cell::sync::Lazy;
use std::env;
use std::fs;
use std::path::Path;

pub static HOME: Lazy<String> =
    Lazy::new(|| env::var("HOME").unwrap_or_else(|_| panic!("Error: $HOME is not set.")));

// If PASSWORD_STORE_DIR is not set, default to "$HOME/.password-store"
pub static PREFIX: Lazy<String> = Lazy::new(|| {
    env::var("PASSWORD_STORE_DIR").unwrap_or_else(|_| format!("{}/.password-store", *HOME))
});

/// Checks for potentially dangerous path segments in the provided paths.
///
/// This function iterates over each path string in the given vector and verifies that it does
/// not contain any suspicious patterns that could be used for directory traversal attacks. Specifically,
/// it checks if a path:
/// - Ends with `/..`
/// - Starts with `../`
/// - Contains `/../`
/// - Is exactly equal to `..`
///
/// If any of these conditions are met, the function will panic with an error message. This is a
/// security measure to prevent passing "sneaky" paths into the application.
///
/// # Arguments
///
/// * `paths` - A vector of string slices, each representing a file or directory path.
///
/// # Panics
///
/// The function panics if any path is found that contains sneaky segments, with a message:
/// "Error: You've attempted to pass a sneaky path to pass. Go home."
///
/// # Examples
///
/// ```rust
/// // This example will panic because "../unsafe/path" contains a dangerous pattern.
/// let paths = vec!["safe/path", "../unsafe/path"];
/// check_sneaky_paths(paths);
/// ```
pub fn check_sneaky_paths(paths: Vec<&str>) {
    for path in paths {
        if path.ends_with("/..") || path.starts_with("../") || path.contains("/../") || path == ".."
        {
            panic!("Error: You've attempted to pass a sneaky path to pass. Go home.");
        }
    }
}

/// Recursively prints the directory structure starting from the given path.
///
/// This function traverses the directory tree beginning at `path` and prints each entry
/// (file or directory) along with a prefix to indicate its depth in the hierarchy. Hidden
/// files (those starting with a dot) are skipped. Additionally, if a file has a `.gpg`
/// extension, the extension is removed when printing the file name.
///
/// # Arguments
///
/// * `path` - A reference to the [`std::path::Path`] that represents the root directory
///            from which to start printing the structure.
/// * `prefix` - A string used as a prefix for each printed entry to indicate the current
///              depth in the directory tree. This should typically be an empty string when
///              first called, and it will be extended recursively.
///
/// # Returns
///
/// A [`std::io::Result<()>`] which is:
/// - `Ok(())` if the directory structure was successfully printed.
/// - An error if there was a problem reading one or more directory entries.
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use your_crate::utils::print_dir_structure; // Adjust the import path as needed
///
/// // Print the structure of the current directory.
/// if let Err(e) = print_dir_structure(Path::new("."), "".to_string()) {
///     eprintln!("Error printing directory structure: {}", e);
/// }
/// ```
///
/// # Notes
///
/// This function directly prints the directory structure to standard output and uses recursion
/// to traverse subdirectories. Make sure the provided `path` exists and is a directory.
pub fn print_dir_structure(path: &Path, prefix: String) -> std::io::Result<()> {
    if path.is_dir() {
        for entry_result in fs::read_dir(path)? {
            let entry = entry_result?;
            let path = entry.path();
            let filename = path.file_name().unwrap().to_str().unwrap();

            if path.is_dir() {
                println!("{}─ {}", prefix, filename);
                let new_prefix = format!("{}    ", prefix);
                print_dir_structure(&path, new_prefix)?;
            } else {
                if filename.starts_with(".") {
                    continue;
                }
                if filename.ends_with(".gpg") {
                    println!("{}─ {}", prefix, &filename[..filename.len() - 4]);
                } else {
                    println!("{}─ {}", prefix, filename);
                }
            }
        }
    }
    Ok(())
}
