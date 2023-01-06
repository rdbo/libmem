use libmem::*;

fn main() {
    println!("test");
    let process = LM_GetProcess().unwrap();
    println!("Process ID: {}", process.get_pid());
    println!("Process Parent PID: {}", process.get_ppid());
    println!("Process Bits: {}", process.get_bits());
    println!("Process Path: {}", process.get_path());
    println!("Process Name: {}", process.get_name());

    for proc in LM_EnumProcesses() {
        println!("{} | {} | {} | {} | {}", proc.get_pid(), proc.get_ppid(), proc.get_bits(), proc.get_path(), proc.get_name());
    }
}
