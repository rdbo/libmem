use libmem::*;

fn main() {
    for module in LM_EnumModules().unwrap() {
        println!("[*] Module Base: {:#x}", module.get_base());
        println!("[*] Module End:  {:#x}", module.get_end());
        println!("[*] Module Size: {:#x}", module.get_size());
        println!("[*] Module Name: {}", module.get_name());
        println!("[*] Module Path: {}", module.get_path());
        println!("====================")
    }
}
