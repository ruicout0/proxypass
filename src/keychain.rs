use anyhow::{Context, Result};
use keyring::Entry;

const SERVICE: &str = "proxypass";

pub fn set_password(username: &str, password: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, username)
        .context("Failed to access keychain")?;
    entry.set_password(password)
        .context("Failed to store password in keychain")?;
    println!("Password stored in keychain for user '{}'", username);
    Ok(())
}

pub fn get_password(username: &str) -> Result<String> {
    let entry = Entry::new(SERVICE, username)
        .context("Failed to access keychain")?;
    entry.get_password()
        .with_context(|| format!("No password found in keychain for user '{}'", username))
}

