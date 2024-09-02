use std::{
    ffi::{c_void, CStr, CString},
    mem::size_of,
    path::PathBuf,
};

use windows::{
    core::{Error, PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, FARPROC, HINSTANCE},
        Security::{
            GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY,
            TOKEN_USER,
        },
        Storage::FileSystem::GetTempPathA,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                TH32CS_SNAPPROCESS,
            },
            LibraryLoader::{GetModuleFileNameA, GetModuleHandleA, GetProcAddress},
            Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION},
        },
        UI::Shell::GetUserProfileDirectoryW,
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
pub fn get_temp_path() -> Option<PathBuf> {
    let mut path = vec![0u8; 1024];
    // this should never fail
    let l = unsafe { GetTempPathA(Some(&mut path)) };

    if l == 0 {
        return None;
    }

    for _ in l..1024 {
        path.pop();
    }

    String::from_utf8(path).map(PathBuf::from).ok()
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

#[allow(unused)]
pub struct ProcessOwner {
    pub domain: String,
    pub username: String,
    pub profile_path: PathBuf,
}

#[allow(unused)]
pub fn get_process_owner(pid: u32) -> Result<ProcessOwner, Error> {
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)? };

    let mut proc_token = windows::Win32::Foundation::HANDLE(0);
    unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut proc_token as *mut _)? };

    let mut owner_length = size_of::<TOKEN_USER>() as u32;

    unsafe {
        GetTokenInformation(proc_token, TokenUser, None, 0, &mut owner_length as *mut _).ok();
    }

    let mut owner = vec![0u8; owner_length as usize];

    unsafe {
        GetTokenInformation(
            proc_token,
            TokenUser,
            Some(owner.as_mut_ptr() as *mut c_void),
            owner_length,
            &mut owner_length as *mut _,
        )?;
    }

    let owner: TOKEN_USER = unsafe { std::ptr::read(owner.as_ptr() as *mut _) };

    let mut username = [0u16; 256];
    let mut username_length = 256u32;
    let mut domain = [0u16; 256];
    let mut domain_length = 256u32;
    let mut sid_type = SID_NAME_USE::default();

    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            owner.User.Sid,
            PWSTR(username.as_mut_ptr()),
            &mut username_length as *mut _,
            PWSTR(domain.as_mut_ptr()),
            &mut domain_length as *mut _,
            &mut sid_type as *mut _,
        )?;
    }

    let mut profile_path = [0u16; 512];
    let mut profile_path_length = 512u32;

    unsafe {
        GetUserProfileDirectoryW(
            proc_token,
            PWSTR(profile_path.as_mut_ptr()),
            &mut profile_path_length as *mut _,
        )?;
    }

    if profile_path_length > 0 && profile_path[profile_path_length as usize - 1] == 0 {
        profile_path_length -= 1;
    }

    unsafe {
        CloseHandle(proc_token).ok();
        CloseHandle(proc_handle).ok();
    }

    let owner = ProcessOwner {
        domain: String::from_utf16(&domain[..domain_length as usize]).unwrap(),
        username: String::from_utf16(&username[..username_length as usize]).unwrap(),
        profile_path: PathBuf::from(
            String::from_utf16(&profile_path[..profile_path_length as usize]).unwrap(),
        ),
    };

    Ok(owner)
}
