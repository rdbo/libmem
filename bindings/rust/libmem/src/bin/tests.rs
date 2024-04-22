use libmem::{find_module, get_process};

pub fn main() {
    let process = get_process().unwrap();
    println!("{}", process);

    let module = find_module(&process.name).unwrap();
    println!("{}", module);
}
