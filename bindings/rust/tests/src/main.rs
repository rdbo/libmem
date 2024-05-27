use libmem::{
    demangle_symbol, enum_modules, enum_modules_ex, enum_processes, enum_segments,
    enum_segments_ex, enum_symbols, enum_symbols_demangled, find_module, find_module_ex,
    find_process, find_segment, find_segment_ex, find_symbol_address,
    find_symbol_address_demangled, get_bits, get_process, get_process_ex, get_system_bits,
    get_thread, get_thread_ex, get_thread_process, is_process_alive, load_module, load_module_ex,
    read_memory, set_memory, unload_module, unload_module_ex, write_memory, Address,
};

pub fn main() {
    let processes = enum_processes().unwrap();
    println!("[*] Process Enumeration: ");
    println!(" - {}", processes.first().unwrap());
    println!("...");
    println!(" - {}", processes.last().unwrap());
    println!("Process Count: {}", processes.len());
    println!();

    let process = get_process().unwrap();
    println!("[*] Current Process: {}", process);

    let target_process = find_process("target").unwrap();
    println!("[*] Target Process: {}", target_process);

    println!(
        "[*] Target Process (got by PID): {}",
        get_process_ex(target_process.pid).unwrap()
    );

    println!(
        "[*] Is Target Process Alive? {}",
        is_process_alive(&target_process)
    );

    println!();

    println!("[*] Process Bits: {}", get_bits());
    println!("[*] System Bits: {}", get_system_bits());

    println!("================================");

    let thread = get_thread().unwrap();
    println!("[*] Current Thread: {}", thread);

    let target_thread = get_thread_ex(&target_process).unwrap();
    println!("[*] Target Thread: {}", target_thread);

    let thread_process = get_thread_process(&target_thread).unwrap();
    println!("[*] Target Thread Process: {}", thread_process);

    println!("================================");

    let modules = enum_modules().unwrap();
    println!("[*] Module Enumeration: ");
    println!(" - {}", modules.first().unwrap());
    println!("...");
    println!(" - {}", modules.last().unwrap());
    println!("Module Count: {}", modules.len());
    println!();

    let modules = enum_modules_ex(&target_process).unwrap();
    println!("[*] Target Module Enumeration: ");
    println!(" - {}", modules.first().unwrap());
    println!("...");
    println!(" - {}", modules.last().unwrap());
    println!("Module Count: {}", modules.len());
    println!();

    let module = find_module(&process.name).unwrap();
    println!("[*] Process Module: {}", module);

    let target_module = find_module_ex(&target_process, &target_process.name).unwrap();
    println!("[*] Target Process Module: {}", target_module);

    let libpath = format!(
        "{}/../../build/tests/libtest.so",
        std::env::current_dir().unwrap().display()
    );
    println!("[*] Library Path: {}", libpath);
    let loaded_module = load_module(&libpath).unwrap();
    println!("[*] Module Loaded: {}", loaded_module);
    unload_module(&loaded_module).unwrap();
    println!("[*] Unloaded Module");

    let target_loaded_module = load_module_ex(&target_process, &libpath).unwrap();
    println!("[*] Module Loaded in Target: {}", target_loaded_module);
    unload_module_ex(&target_process, &target_loaded_module).unwrap();
    println!("[*] Unloaded Module from Target Process");

    println!("================================");

    let symbols = enum_symbols(&target_module).unwrap();
    println!("[*] Symbol Enumeration: ");
    println!(" - {}", symbols.first().unwrap());
    println!("...");
    println!(" - {}", symbols.last().unwrap());

    let main_symbol = find_symbol_address(&target_module, "main").unwrap();
    println!("[*] Target 'main': {}", main_symbol);

    let mangled_symbol = "_ZN4llvm11ms_demangle14ArenaAllocator5allocINS0_29LiteralOperatorIdentifierNodeEJEEEPT_DpOT0_";
    println!(
        "[*] Demangled symbol '{}': {}",
        mangled_symbol,
        demangle_symbol(&mangled_symbol).unwrap()
    );

    let symbols = enum_symbols_demangled(&target_module).unwrap();
    println!("[*] Demangled Symbol Enumeration: ");
    println!(" - {}", symbols.first().unwrap());
    println!("...");
    println!(" - {}", symbols.last().unwrap());

    let main_symbol_demangle = find_symbol_address_demangled(&module, "main").unwrap();
    println!("[*] 'main': {}", main_symbol_demangle);

    println!("================================");

    let segments = enum_segments().unwrap();
    println!("[*] Segment Enumeration: ");
    println!(" - {}", segments.first().unwrap());
    println!("...");
    println!(" - {}", segments.last().unwrap());
    println!();

    let segments = enum_segments_ex(&target_process).unwrap();
    println!("[*] Target Segment Enumeration: ");
    println!(" - {}", segments.first().unwrap());
    println!("...");
    println!(" - {}", segments.last().unwrap());
    println!();

    let segment = find_segment(module.base).unwrap();
    println!("[*] Segment at module '{}' base: {}", module.name, segment);

    let segment = find_segment_ex(&target_process, target_module.base).unwrap();
    println!(
        "[*] Segment at target module '{}' base: {}",
        target_module.name, segment,
    );

    println!("================================");

    let number: i32 = 10;
    let number_addr = &number as *const i32 as Address;
    let read_number = unsafe { read_memory::<i32>(number_addr) };
    println!("[*] Read memory from number: {}", read_number);
    unsafe { write_memory::<i32>(number_addr, &1337) };
    println!("[*] Wrote new memory on number: {}", number);
    unsafe { set_memory(number_addr, 0, std::mem::size_of_val(&number)) };
    println!("[*] Zeroed number memory: {}", number);

    println!("================================");
}
