# password-store-rs

A `pass`-inspired password manager written in Rust. Encrypts your secrets using GPG and optionally tracks them in Git.

## ✨ Features

- 🔐 GPG-based encryption for each password entry
- 🗃️ Simple file-based storage (compatible layout with `pass`)
- 🧾 Git integration for version control (optional)
- 💻 Command-line interface built with `clap`
- 🦀 Written in safe, modern Rust

## 📦 Installation

Clone and build locally:

```sh
git clone https://github.com/yourusername/password-store-rs.git
cd password-store-rs
cargo build --release
```

Or install directly from GitHub:

```sh
cargo install --git https://github.com/yourusername/password-store-rs
```

> Replace `yourusername` with your actual GitHub username.

## 🚀 Quick Start

Initialize the password store (generate a new GPG key if needed):

```sh
password-store-rs init --auto
```

Or initialize with an existing GPG key:

```sh
password-store-rs init 34E8F4A6A3851A5C
```

Add a new password:

```sh
password-store-rs add example.com
```

Show a password:

```sh
password-store-rs show example.com
```

Search for entries:

```sh
password-store-rs find email
```

## 📁 File Structure

Secrets are stored in:

```
$HOME/.password-store/
├── example.com.gpg
├── email/
│   └── gmail.com.gpg
└── .gpg-id
```

## 📚 Related Projects

- [pass](https://www.passwordstore.org/) — The original Unix password manager
- [gpg](https://gnupg.org) — GNU Privacy Guard
- [git](https://git-scm.com) — Distributed version control

## 🛡 Security

Secrets are encrypted using the GPG key(s) listed in `.gpg-id`. Signing with a `PASSWORD_STORE_SIGNING_KEY` is also supported.

## 📜 License

MIT © 2025 Ricky Nelson

