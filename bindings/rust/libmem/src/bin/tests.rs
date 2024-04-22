use libmem::get_process;

pub fn main() {
    let process = get_process().unwrap();
    println!("{}", process);
}
