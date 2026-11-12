//! Names scoped to a workspace, for the keys, rooms and prefixes a host builds (layer: domain).
//!
//! The name is the concatenation, for the tenant, the workspace and then every part in order, of
//! `<byte length>:<text>`, where the length is the number of UTF-8 bytes of the text in canonical
//! decimal. A length-prefixed piece is self-delimiting, so no text can move a boundary: two
//! different argument lists never produce one name. `@bymax-one/nest-auth` builds the same name
//! from the same arguments, which is the point: a host that runs both gets one keyspace.
//!
//! Refused: a piece holding a C0 control (U+0000 to U+001F) or DEL (U+007F), because several
//! storage backends reject or mangle them, and an empty tenant or workspace. An empty part is
//! allowed and is a piece of its own. An unpaired surrogate cannot be expressed in a `&str`, so the
//! type system refuses it before this function is reached.

/// Why a scoped name could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopedNameError {
    /// A piece holds a C0 control character or DEL.
    #[error("a piece contains a control character")]
    ControlCharacter,
    /// The tenant is empty.
    #[error("the tenant is empty")]
    EmptyTenant,
    /// The workspace is empty.
    #[error("the workspace is empty")]
    EmptyWorkspace,
}

/// Whether `piece` holds a C0 control character or DEL.
fn has_control(piece: &str) -> bool {
    piece.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}

/// The name of `parts` inside `tenant_id`'s `workspace_id`.
///
/// # Errors
///
/// [`ScopedNameError`] for an empty tenant or workspace, or any piece with a control character.
pub fn workspace_scoped_name(
    tenant_id: &str,
    workspace_id: &str,
    parts: &[&str],
) -> Result<String, ScopedNameError> {
    if tenant_id.is_empty() {
        return Err(ScopedNameError::EmptyTenant);
    }
    if workspace_id.is_empty() {
        return Err(ScopedNameError::EmptyWorkspace);
    }
    let mut name = String::new();
    for piece in [tenant_id, workspace_id]
        .into_iter()
        .chain(parts.iter().copied())
    {
        if has_control(piece) {
            return Err(ScopedNameError::ControlCharacter);
        }
        name.push_str(&piece.len().to_string());
        name.push(':');
        name.push_str(piece);
    }
    Ok(name)
}
