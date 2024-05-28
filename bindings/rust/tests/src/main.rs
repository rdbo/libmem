use libmem::{
    alloc_memory, alloc_memory_ex, assemble, assemble_ex, data_scan, data_scan_ex, deep_pointer,
    deep_pointer_ex, demangle_symbol, enum_modules, enum_modules_ex, enum_processes, enum_segments,
    enum_segments_ex, enum_symbols, enum_symbols_demangled, find_module, find_module_ex,
    find_process, find_segment, find_segment_ex, find_symbol_address,
    find_symbol_address_demangled, free_memory, free_memory_ex, get_bits, get_process,
    get_process_ex, get_system_bits, get_thread, get_thread_ex, get_thread_process,
    is_process_alive, load_module, load_module_ex, pattern_scan, pattern_scan_ex, prot_memory,
    prot_memory_ex, read_memory, read_memory_ex, set_memory, set_memory_ex, sig_scan, sig_scan_ex,
    unload_module, unload_module_ex, write_memory, write_memory_ex, Address, Arch, Bits, Prot,
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

    let alloc = alloc_memory(0, Prot::XRW).unwrap();
    println!("[*] Allocated Memory: {:#x}", alloc);
    println!("[*] Allocated Segment: {}", find_segment(alloc).unwrap());

    let old_prot = prot_memory(alloc, 0, Prot::R).unwrap();
    println!("[*] Previous Protection: {}", old_prot);
    println!("[*] Memory Segment: {}", find_segment(alloc).unwrap());

    free_memory(alloc, 0);
    println!("[*] Freed memory");
    println!("[*] Memory Segment: {:?}", find_segment(alloc));

    #[repr(C)]
    struct Player {
        pad: [u8; 0xF0],
        health: i32,
    }

    #[repr(C)]
    struct PointerLayer {
        player_ptr: *const Player,
    }

    let player = Player {
        pad: [0; 0xF0],
        health: 42,
    };

    let pointer_base = PointerLayer {
        player_ptr: &player as *const Player,
    };
    println!("[*] Player Health: {}", player.health);

    let pointer_base_addr = &pointer_base as *const PointerLayer as Address;
    let player_health_ptr = &(player.health) as *const i32;
    let health_ptr = unsafe { deep_pointer::<i32>(pointer_base_addr, &vec![0xF0]) };
    println!(
        "[*] Health Pointer: {:?} (expected: {:?})",
        health_ptr, player_health_ptr
    );
    unsafe {
        *health_ptr = 1337;
    }
    println!(
        "[*] Player Health (after modifying value): {}",
        player.health
    );

    let target_alloc = alloc_memory_ex(&target_process, 1024, Prot::XRW).unwrap();
    println!("[*] Target Allocated Memory: {:#x}", target_alloc);
    println!(
        "[*] Target Memory Segment: {}",
        find_segment_ex(&target_process, target_alloc).unwrap()
    );

    write_memory_ex(&target_process, target_alloc, &1337).unwrap();
    println!("[*] Wrote number to the target process memory");

    set_memory_ex(&target_process, target_alloc + 4, 0xFF, 4).unwrap();
    println!("[*] Set bytes on the target process memory");

    let (written_number, set_number) =
        read_memory_ex::<(i32, i32)>(&target_process, target_alloc).unwrap();
    println!(
        "[*] Read numbers from target alloc: {}, {}",
        written_number, set_number
    );

    prot_memory_ex(&target_process, target_alloc, 0, Prot::RW).unwrap();
    println!(
        "[*] Changed Protection of Target Alloc: {}",
        find_segment_ex(&target_process, target_alloc).unwrap()
    );

    let target_player_ptr = target_alloc + std::mem::size_of::<PointerLayer>();
    let target_pointer_base = PointerLayer {
        player_ptr: target_player_ptr as *const Player,
    };
    let player = Player {
        pad: [0; 0xF0],
        health: 42,
    };
    write_memory_ex(&target_process, target_alloc, &target_pointer_base);
    write_memory_ex(&target_process, target_player_ptr, &player);
    let target_health_ptr = deep_pointer_ex(&target_process, target_alloc, &vec![0xF0]).unwrap();
    println!("[*] Target Player Health Ptr: {:#x}", target_health_ptr);
    let target_health = read_memory_ex::<i32>(&target_process, target_health_ptr).unwrap();
    println!("[*] Target Player Health: {}", target_health);

    free_memory_ex(&target_process, target_alloc, 0);
    println!("[*] Freed Allocated Target Memory");
    println!(
        "[*] Target Memory Segment: {:?}",
        find_segment_ex(&target_process, target_alloc)
    );

    println!("================================");

    let buffer: [u8; 14] = [0, 3, 4, 1, 2, 6, 0x10, 0x20, 0x30, 0, 0, 5, 2, 6];
    let buffer_addr = buffer.as_ptr() as Address;
    let buffer_size = buffer.len() * std::mem::size_of::<u8>();
    let expected = &buffer[6] as *const u8;
    println!("[*] Buffer Address: {:#x}", buffer_addr);
    println!("[*] Expected Address: {:?}", expected);

    let data: [u8; 3] = [0x10, 0x20, 0x30];
    let scan = unsafe { data_scan(&data, buffer_addr, buffer_size).unwrap() };
    println!("[*] Data Scan Result: {:?}", scan);
    println!("[*] Data Scan Deref: {:?}", unsafe { *scan });

    let pattern: [u8; 7] = [0x10, 0, 0x30, 0, 0, 5, 2];
    let mask = "x?x??xx";
    let scan = unsafe { pattern_scan(&pattern, &mask, buffer_addr, buffer_size).unwrap() };
    println!("[*] Pattern Scan Result: {:#x}", scan);

    let signature = "10 ?? 30 ?? ?? 05 02";
    let scan = unsafe { sig_scan(signature, buffer_addr, buffer_size).unwrap() };
    println!("[*] Signature Scan Result: {:#x}", scan);

    println!();

    let target_buffer_addr = alloc_memory_ex(&target_process, 0, Prot::XRW).unwrap();
    println!("[*] Target Buffer Address: {:#x}", target_buffer_addr);

    write_memory_ex(&target_process, target_buffer_addr, &buffer).unwrap();
    println!(
        "[*] Wrote buffer to target: {:?}",
        read_memory_ex::<[u8; 14]>(&target_process, target_buffer_addr).unwrap()
    );

    let expected = target_buffer_addr + 6;
    println!("[*] Expected Scan Result: {:#x}", expected);

    let scan = data_scan_ex(&target_process, &data, target_buffer_addr, buffer_size).unwrap();
    println!("[*] Target Data Scan Result: {:#x}", scan);

    let scan = pattern_scan_ex(
        &target_process,
        &pattern,
        &mask,
        target_buffer_addr,
        buffer_size,
    )
    .unwrap();
    println!("[*] Target Pattern Scan Result: {:#x}", scan);

    let scan = sig_scan_ex(&target_process, signature, target_buffer_addr, buffer_size).unwrap();
    println!("[*] Target Signature Scan Result: {:#x}", scan);

    free_memory_ex(&target_process, target_buffer_addr, 0);

    println!("================================");

    let inst = assemble("mov eax, ebx").unwrap();
    println!("[*] Assembled Instruction: {}", inst);

    let payload = assemble_ex(
        "push rbp; mov rbp, rsp; mov rsp, rbp; pop rbp; ret",
        Arch::X86,
        Bits::Bits64,
        0xdeadbeef,
    )
    .unwrap();

    println!("[*] Assembled Payload: {:?}", payload);
}
