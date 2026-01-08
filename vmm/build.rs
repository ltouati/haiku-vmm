use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=init.sh");
    println!("cargo:rerun-if-changed=create_image.sh");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let project_root = Path::new(&out_dir);
    let work_dir = project_root.join("initrd_work");
    let output_img = project_root.join("debug_initrd.img");
    let init_source = Path::new("init.sh");

    println!("Creating initrd at {:?}", output_img);

    for dir in &["bin", "dev", "proc", "sys", "mnt", "tmp", "etc"] {
        fs::create_dir_all(work_dir.join(dir)).unwrap();
    }

    let busybox_path = work_dir.join("bin/busybox");

    if !busybox_path.exists() {
        println!("Static busybox not found on system. Downloading...");

        // URL for the official static x86_64 binary
        let url = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";

        let status = Command::new("curl")
            .args(["-L", "-o", busybox_path.to_str().unwrap(), url])
            .status()
            .expect(
                "Failed to execute curl. Please install curl or provide a static busybox binary.",
            );

        if !status.success() {
            panic!("Failed to download busybox from {}", url);
        }
    }

    // Ensure busybox is executable
    let mut perms = fs::metadata(&busybox_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&busybox_path, perms).unwrap();

    let strace_path = work_dir.join("bin/strace");
    if !strace_path.exists() {
        println!("Static strace not found. Downloading...");
        let url = "https://raw.githubusercontent.com/yunchih/static-binaries/master/strace";
        let status = Command::new("curl")
            .args(["-L", "-o", strace_path.to_str().unwrap(), url])
            .status()
            .expect("Failed to execute curl for strace");

        if !status.success() {
            panic!("Failed to download strace from {}", url);
        }
    }
    // Ensure strace is executable
    let mut perms = fs::metadata(&strace_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&strace_path, perms).unwrap();
    // Create essential symlinks for troubleshooting tools
    let tools = [
        "sh", "ls", "cat", "mount", "umount", "mkdir", "mknod", "hexdump", "uname", "sleep", "ps",
    ];
    for tool in tools {
        let link_path = work_dir.join("bin").join(tool);
        // We use busybox as the target for all these tools
        if !link_path.exists() {
            std::os::unix::fs::symlink("busybox", link_path).unwrap();
        }
    }

    // 3. Copy the Init Script
    let target_init = work_dir.join("init");
    fs::copy(init_source, &target_init).unwrap();

    // Ensure init is executable
    let mut perms = fs::metadata(&target_init).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&target_init, perms).unwrap();
    let create_image_script = Path::new("create_image.sh");
    println!("{:?}", work_dir);
    // 4. Create the CPIO archive
    // We use a pipe: find . | cpio -o -H newc | gzip > ../debug_initrd.img
    let find_output = Command::new("bash")
        .args([
            "-c",
            create_image_script
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap(),
        ])
        .current_dir(&work_dir)
        .output()
        .expect("failed to run find");
    println!("{:?}", find_output);
    fs::copy(&output_img, Path::new("../kernels/initrd.img")).expect("failed to copy image");
    println!("Successfully built initrd: {:?}", output_img);
}
