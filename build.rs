//! Build script that embeds the Windows PE icon and version resource metadata.

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/icon.png");

    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "Local User and Group Management");
        res.set(
            "FileDescription",
            "Local User and Group Management (lusrmgr) - Windows user and group administration tool",
        );
        res.set("OriginalFilename", "lusrmgr.exe");
        res.set(
            "LegalCopyright",
            "Copyright (C) 2019-2021 akruhler, 2026 Aaron Christopher Ramos",
        );
        res.compile()
            .expect("Failed to compile Windows icon and version resource.");
    }
}
