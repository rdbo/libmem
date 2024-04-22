use libmem::{enum_processes, find_module, get_process};

pub fn main() {
    let processes = enum_processes().unwrap();
    println!("{:?}", processes);

    let process = get_process().unwrap();
    println!("{}", process);

    let module = find_module(&process.name).unwrap();
    println!("{}", module);
}
