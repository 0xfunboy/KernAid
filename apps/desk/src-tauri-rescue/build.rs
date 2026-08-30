fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new()
                .commands(&["rescue_native_prompt_status", "open_rescue_native_prompt"]),
        ),
    )
    .expect("build the closed Rescue native-prompt ACL");
}
