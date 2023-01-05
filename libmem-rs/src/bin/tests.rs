use libmem::*;

fn main() {
    println!("test");
    let process = LM_GetProcess().unwrap();
    println!("Process ID: {}", process.get_pid());
    println!("Process Parent PID: {}", process.get_ppid());
    println!("Process Bits: {}", process.get_bits());
    println!("Process Path: {}", process.get_path());
    println!("Process Name: {}", process.get_name());
}
