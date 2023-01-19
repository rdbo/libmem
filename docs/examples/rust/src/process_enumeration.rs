use libmem::*;

fn main() {
    for process in LM_EnumProcesses().unwrap() {
        println!("[*] Process PID:  {}", process.get_pid());
        println!("[*] Process PPID: {}", process.get_ppid());
        println!("[*] Process Name: {}", process.get_name());
        println!("[*] Process Path: {}", process.get_path());
        println!("[*] Process Bits: {}", process.get_bits());
        println!("====================")
    }
}
