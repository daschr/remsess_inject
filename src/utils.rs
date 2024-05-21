use std::{
    ffi::{CStr, CString},
    mem::size_of,
};

use windows::{
    core::{Error, PCSTR},
    Win32::{
        Foundation::{CloseHandle, FARPROC, HINSTANCE},
        Storage::FileSystem::GetTempPathA,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                TH32CS_SNAPPROCESS,
            },
            LibraryLoader::{GetModuleFileNameA, GetModuleHandleA, GetProcAddress},
        },
    },
};

#[allow(unused)]
pub fn get_module_name(handle: HINSTANCE) -> Option<String> {
    let mut path = vec![0u8; 1024];
    // this should never fail
    let l = unsafe { GetModuleFileNameA(handle, &mut path) };

    if l == 0 {
        return None;
    }

    for _ in l..1024 {
        path.pop();
    }

    String::from_utf8(path).ok()
}

#[allow(unused)]
pub fn get_temp_path() -> Option<String> {
    let mut path = vec![0u8; 1024];
    // this should never fail
    let l = unsafe { GetTempPathA(Some(&mut path)) };

    if l == 0 {
        return None;
    }

    for _ in l..1024 {
        path.pop();
    }

    String::from_utf8(path).ok()
}

#[allow(unused)]
pub fn get_proc_address(library_name: &str, fn_name: &str) -> Result<FARPROC, Error> {
    let lib_name = CString::new(library_name).unwrap();

    let lib_handle = unsafe { GetModuleHandleA(PCSTR::from_raw(lib_name.into_raw() as *mut u8))? };

    let fn_name: CString = CString::new(fn_name).unwrap();

    unsafe {
        Ok(GetProcAddress(
            lib_handle,
            PCSTR::from_raw(fn_name.into_raw() as *mut u8),
        ))
    }
}

#[allow(unused)]
pub fn find_processes_by_name(name: &str) -> Result<Option<Vec<u32>>, Error> {
    let proc_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

    let mut cur_proc: PROCESSENTRY32 = PROCESSENTRY32 {
        dwSize: size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut proc_list = Vec::new();

    unsafe {
        Process32First(proc_snapshot, (&mut cur_proc) as *mut _)?;
    }

    loop {
        let cur_proc_name =
            unsafe { CStr::from_ptr(cur_proc.szExeFile.as_slice().as_ptr()).to_string_lossy() };

        // println!("Process: {}: {}", cur_proc.th32ProcessID, cur_proc_name);

        if cur_proc_name == name {
            proc_list.push(cur_proc.th32ProcessID);
        }

        unsafe {
            if let Err(e) = Process32Next(proc_snapshot, (&mut cur_proc) as *mut _) {
                // eprintln!("Got error while iterating with Process32Next: {:?}", e);
                break;
            }
        }
    }

    unsafe { CloseHandle(proc_snapshot)? };

    Ok(if proc_list.is_empty() {
        None
    } else {
        Some(proc_list)
    })
}
