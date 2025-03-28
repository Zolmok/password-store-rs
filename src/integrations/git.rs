use std::path::Path;
use std::process::Command;

/// Adds a file to Git and commits the change with the provided commit message.
///
/// This function first checks if the file is within a Git repository by attempting to
/// retrieve the repository top-level directory from the file's parent. If the file is
/// not inside a Git repository, the function logs a warning and returns `Ok(())`.
///
/// # Arguments
///
/// * `file_path` - The path to the file that should be added to Git.
/// * `message` - The commit message to use when committing the file.
///
/// # Returns
///
/// * `Ok(())` if the file is added (and committed) successfully, or if the file is not in a Git repository.
/// * `Err(String)` if there is an error executing either the `git add` or `git commit` command.
pub fn git_add_file(file_path: &str, message: &str) -> Result<(), String> {
    // Determine the parent directory of the file.
    let file_parent = Path::new(file_path)
        .parent()
        .ok_or_else(|| format!("Could not determine parent directory of {}", file_path))?;

    // Check if the parent directory is inside a Git repository.
    let repo_toplevel = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .current_dir(file_parent)
        .output();

    // If the file is not inside a Git repository, return Ok(()) silently.
    if repo_toplevel.is_err() || !repo_toplevel.unwrap().status.success() {
        return Ok(());
    }

    // Run "git add <file_path>"
    let add_status = match Command::new("git")
        .args(&["add", file_path])
        .status()
        .map_err(|e| format!("Failed to execute git add: {}", e))
    {
        Ok(status) => status,
        Err(err) => return Err(err),
    };

    if !add_status.success() {
        return Err(format!(
            "git add command failed with status: {}",
            add_status
        ));
    }

    // Run "git commit -m <message> <file_path>"
    let commit_status = match Command::new("git")
        .args(&["commit", "-m", message, file_path])
        .status()
        .map_err(|e| format!("Failed to execute git commit: {}", e))
    {
        Ok(status) => status,
        Err(err) => return Err(err),
    };

    if !commit_status.success() {
        // It's common that there's nothing new to commit. We warn and continue.
        println!("Warning: git commit returned non-zero (possibly nothing to commit).");
    }

    Ok(())
}

/// Removes a file from Git and commits the removal with the provided commit message.
///
/// This function runs `git rm <file_path>` to remove the file from version control,
/// then stages and commits the removal with `git commit -m <message> <file_path>`.
///
/// # Arguments
///
/// * `file_path` - The path to the file that should be removed from Git.
/// * `message` - The commit message to use when committing the file removal.
///
/// # Examples
///
/// ```rust
/// // Remove a file from Git with a commit message.
/// git_remove_file("path/to/file.txt", "Remove file.txt from repository");
/// ```
pub fn git_remove_file(file_path: &str, message: &str) {
    use std::process::Command;

    // Run "git rm <file_path>".
    let rm_status = Command::new("git").args(&["rm", file_path]).status();

    match rm_status {
        Ok(status) if status.success() => {
            // File successfully removed.
        }
        Ok(status) => {
            println!("Warning: 'git rm' returned non-zero status: {}", status);
        }
        Err(e) => {
            println!(
                "Warning: Failed to execute 'git rm' for {}: {}",
                file_path, e
            );
        }
    }

    // Run "git commit -m <message> <file_path>" to commit the removal.
    let commit_status = Command::new("git")
        .args(&["commit", "-m", message, file_path])
        .status();

    match commit_status {
        Ok(status) if status.success() => {
            // Commit successful.
        }
        Ok(status) => {
            println!("Warning: 'git commit' returned non-zero status: {}", status);
        }
        Err(e) => {
            println!(
                "Warning: Failed to execute 'git commit' for {}: {}",
                file_path, e
            );
        }
    }
}
