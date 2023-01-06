use libmem::*;

fn separator() {
    println!("====================");
}

fn main() {
    println!("[*] libmem-rs tests");

    let mut counter = 0;
    for proc in LM_EnumProcesses() {
        println!("{} | {} | {} | {} | {}", proc.get_pid(), proc.get_ppid(), proc.get_bits(), proc.get_path(), proc.get_name());
        counter += 1;
        if counter >= 5 {
            break;
        }
    }

    separator();

    let cur_proc = LM_GetProcess().unwrap();
    println!("[*] Current Process: {}", cur_proc);

    separator();

    let proc = LM_FindProcess("dwm").unwrap();
    println!("[*] Remote Process: {}", proc);
}
