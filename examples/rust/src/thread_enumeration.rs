use libmem::*;

fn main() {
    println!("[*] Current Threads: {:?}", LM_EnumThreads().unwrap());
}
