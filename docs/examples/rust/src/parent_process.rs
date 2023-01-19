use libmem::*;

fn main() {
    let current_process = LM_GetProcess().expect("[*] Failed to get current process");
    println!("[*] Process ID:          {}", current_process.get_pid());
    println!("[*] Parent Process ID:   {}", current_process.get_ppid());

    let parent_process = LM_GetProcessEx(current_process.get_ppid()).expect("[*] Failed to get parent process");
    println!("[*] Parent Process Name: {}", parent_process.get_name());
}
