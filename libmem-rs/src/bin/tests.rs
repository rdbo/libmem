use libmem::*;

fn separator() {
    println!("====================");
}

fn main() {
    println!("[*] libmem-rs tests");

    let mut counter = 0;
    for proc in LM_EnumProcesses() {
        println!("{}", proc);
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

    let is_alive = LM_IsProcessAlive(&proc);
    println!("[*] Is the remote process alive? {}", if is_alive { "yes" } else { "no" });
}
