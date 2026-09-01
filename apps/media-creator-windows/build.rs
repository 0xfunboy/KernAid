use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=windows/app.manifest");
    println!("cargo:rerun-if-changed=windows/resources.rc");
    println!("cargo:rerun-if-env-changed=KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var_os("CARGO_FEATURE_WINDOWS_WIZARD").is_none()
    {
        return Ok(());
    }

    let anchor = std::env::var("KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR").map_err(|_| {
        "KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR must contain the approved raw Ed25519 public key"
            .to_owned()
    })?;
    let decoded = URL_SAFE_NO_PAD
        .decode(&anchor)
        .map_err(|_| "media bundle trust anchor must be canonical base64url".to_owned())?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != anchor {
        return Err(
            "media bundle trust anchor must be exactly one raw Ed25519 public key".to_owned(),
        );
    }
    embed_resource::compile("windows/resources.rc", embed_resource::NONE)
        .manifest_required()
        .map_err(|error| format!("Windows application manifest is required: {error}"))?;
    Ok(())
}
