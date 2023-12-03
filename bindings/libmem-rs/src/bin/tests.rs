use libmem::*;
use std::fmt;
use std::mem;

fn separator() {
    println!("====================");
}

#[no_mangle]
pub extern "C" fn some_function() {
    println!("[*] Some Function Called!");
}

static mut TRAMPOLINE: (lm_address_t, lm_size_t) = (0, 0);

#[no_mangle]
pub extern "C" fn hk_some_function() {
    println!("[*] Some Function Hooked!");

    // OBS: Calling the trampoline is crashing the program,
    // although the trampoline is correct and so is the hook
    /*
    let orig_func = unsafe {
        mem::transmute::<*const (), extern "C" fn()>(TRAMPOLINE.0 as *const ())
    };
    orig_func();
    */
}

fn print_n<T>(vec: Vec<T>, n: usize)
where
    T: fmt::Display,
{
    for i in 0..n {
        if i >= vec.len() {
            break;
        }

        println!("{}", vec[i]);
    }
}

// Simple memory representation of a C++ class
#[repr(C)]
struct SomeClassVMT {
    pfn_some_function: extern "C" fn(),
}

#[repr(C)]
struct SomeClass {
    vtable: SomeClassVMT,
}

impl SomeClass {
    fn new() -> Self {
        Self {
            vtable: SomeClassVMT {
                pfn_some_function: some_function,
            },
        }
    }

    fn some_function(&self) {
        (self.vtable.pfn_some_function)();
    }
}

unsafe fn test() {
    println!("[*] libmem-rs tests");

    separator();

    println!("[*] Process Enumeration");
    print_n(LM_EnumProcesses().unwrap(), 5);

    separator();

    let cur_proc = LM_GetProcess().unwrap();
    println!("[*] Current Process: {}", cur_proc);

    separator();

    let parent_proc = LM_GetProcessEx(cur_proc.get_ppid()).unwrap();
    println!("[*] Parent Process Of Current Process: {}", parent_proc);

    separator();

    let proc = LM_FindProcess("test1").unwrap();
    println!("[*] Remote Process: {}", proc);

    separator();

    let is_alive = LM_IsProcessAlive(&proc);
    println!(
        "[*] Is the Remote Process Alive? {}",
        if is_alive { "Yes" } else { "No" }
    );

    separator();

    let sysbits = LM_GetSystemBits();
    println!("[*] System Bits: {}", sysbits);

    separator();

    println!(
        "[*] Current Process Threads: {:?}",
        LM_EnumThreads().unwrap()
    );

    separator();

    println!(
        "[*] Remote Process Threads: {:?}",
        LM_EnumThreadsEx(&proc).unwrap()
    );

    separator();

    let thread = LM_GetThread().unwrap();
    println!("[*] Current Thread ID: {}", thread);
    println!(
        "[*] Remote Process Thread ID: {}",
        LM_GetThreadEx(&proc).unwrap()
    );

    separator();

    println!(
        "[*] Process From Thread '{}': {}",
        thread,
        LM_GetThreadProcess(&thread).unwrap()
    );

    separator();

    println!("[*] Current Process - Module Enumeration");
    print_n(LM_EnumModules().unwrap(), 5);

    separator();

    println!("[*] Remote Process - Module Enumeration");
    print_n(LM_EnumModulesEx(&proc).unwrap(), 5);

    separator();

    let cur_module = LM_FindModule(&cur_proc.get_name()).unwrap();
    println!("[*] Current Process Module: {}", cur_module);

    separator();

    let module = LM_FindModuleEx(&proc, &proc.get_name()).unwrap();
    println!("[*] Remote Process Module: {}", module);

    separator();

    let libmodule = LM_LoadModule("/usr/local/lib/libtest.so").unwrap();
    println!("[*] Module Loaded into Current Process: {}", libmodule);

    separator();

    // TODO: Add tests for LM_LoadModuleEx

    // separator();

    // Needs internal fixing
    // LM_UnloadModule(&module).unwrap();
    // println!("[*] Unloaded Module from Current Process: {}", module);

    // separator();

    // TODO: Add tests for LM_UnloadModuleEx

    // separator();

    // TODO: Fix empty symbol list
    /*
    println!("[*] Current Process - Symbol Enumeration");
    println!("[*] Module: {}", cur_module.get_name());
    print_n(LM_EnumSymbols(&cur_module).unwrap(), 5);

    separator();

    let some_function_addr = LM_FindSymbolAddress(&cur_module, "some_function").unwrap();
    println!(
        "[*] Address of 'some_function': {:p}",
        some_function as *const ()
    );
    println!("[*] Symbol Address Lookup:      {:#x}", some_function_addr);

    separator();
    */
    let some_function_addr = some_function as *const () as usize;

    let mangled = "_ZN5tests9separator17h9f5c7cd256d1d06aE";
    let demangled = LM_DemangleSymbol(&mangled).unwrap();
    println!("[*] Demangled '{}': {}", mangled, demangled);

    separator();

    println!("[*] Current Process - Page Enumeration");
    print_n(LM_EnumPages().unwrap(), 5);

    separator();

    println!("[*] Remote Process - Page Enumeration");
    print_n(LM_EnumPagesEx(&proc).unwrap(), 5);

    separator();

    println!(
        "[*] Current Process - Page at: {:#x}",
        cur_module.get_base()
    );
    println!("{}", LM_GetPage(cur_module.get_base()).unwrap());

    separator();

    println!("[*] Remote Process - Page at: {:#x}", module.get_base());
    println!("{}", LM_GetPageEx(&proc, module.get_base()).unwrap());

    separator();

    let number: i32 = 1337;
    let number_addr = &number as *const i32 as usize;
    let read_number: i32 = LM_ReadMemory(number_addr).unwrap();
    println!("[*] Number Value: {}", number);
    println!("[*] Read Number Value: {}", read_number);

    separator();

    // TODO: Add tests for LM_ReadMemoryEx

    // separator();

    let value: i32 = 69;
    LM_WriteMemory(number_addr, &value).unwrap();
    println!("[*] Value to write: {}", value);
    println!("[*] Number Value: {}", number);

    separator();

    // TODO: Add tests for LM_WriteMemoryEx

    // separator();

    let buffer: [u8; 10] = [0; 10];
    println!("[*] Buffer Original: {:?}", buffer);
    LM_SetMemory(
        buffer.as_ptr() as usize,
        255,
        buffer.len() * mem::size_of::<u8>(),
    )
    .unwrap();
    println!("[*] Buffer After LM_SetMemory: {:?}", buffer);

    separator();

    // TODO: Add tests for LM_SetMemoryEx

    // separator();

    let old_prot = LM_ProtMemory(some_function_addr, 0x1000, LM_PROT_XRW).unwrap();
    println!(
        "[*] Original Protection of '{:#x}': {}",
        some_function_addr, old_prot
    );
    let prot = LM_ProtMemory(some_function_addr, 0x1000, old_prot).unwrap();
    println!(
        "[*] Reverted Protection (from '{}' back to '{}')",
        prot, old_prot
    );

    separator();

    let old_prot = LM_ProtMemoryEx(&proc, module.get_base(), 0x1000, LM_PROT_XRW).unwrap();
    println!(
        "[*] Remote - Original Protection of '{:#x}': {}",
        module.get_base(),
        old_prot
    );
    let prot = LM_ProtMemoryEx(&proc, module.get_base(), 0x1000, old_prot).unwrap();
    println!(
        "[*] Remote - Reverted Protection (from '{}' back to '{}')",
        prot, old_prot
    );

    separator();

    let alloc = LM_AllocMemory(0x1000, LM_PROT_XRW).unwrap();
    println!("[*] Allocated Memory: {:#x}", alloc);
    LM_FreeMemory(alloc, 0x1000).unwrap();
    println!("[*] Freed Memory");

    separator();

    let alloc = LM_AllocMemoryEx(&proc, 0x1000, LM_PROT_XRW).unwrap();
    println!("[*] Remote - Allocated Memory: {:#x}", alloc);
    LM_FreeMemoryEx(&proc, alloc, 0x1000).unwrap();
    println!("[*] Remote - Freed Memory");

    separator();

    let scan_me: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let scan_me_addr = scan_me.as_ptr() as lm_address_t;
    let scan_start = scan_me_addr - 0x10; // start the scan before the 'scan_me' address
    let scan_size = 0xFF;
    let data_scan = LM_DataScan(&scan_me, scan_start, scan_size).unwrap();
    let pattern_scan = LM_PatternScan(&scan_me, "xxxx?xxxx?", scan_start, scan_size).unwrap();
    let sig_scan = LM_SigScan("01 02 03 04 ?? 06 07 08 09 ??", scan_start, scan_size).unwrap();
    println!("[*] Real ScanMe Address: {:#x}", scan_me_addr);
    println!("[*] Data Scan Address: {:#x}", data_scan);
    println!("[*] Pattern Scan Address: {:#x}", pattern_scan);
    println!("[*] Signature Scan Address: {:#x}", sig_scan);

    separator();

    // TODO: Add tests LM_DataScanEx, LM_PatternScanEx, LM_SigScanEx

    // separator();

    println!("[*] Hooking 'some_function'");
    println!("[*] Original Address: {:#x}", some_function_addr);

    TRAMPOLINE = LM_HookCode(
        some_function_addr,
        hk_some_function as *const () as lm_address_t,
    )
    .unwrap();
    println!("[*] Trampoline: {:#x?}", TRAMPOLINE);

    some_function();

    LM_UnhookCode(some_function_addr, TRAMPOLINE).unwrap();

    println!("[*] Unhooked 'some_function'");
    some_function();

    separator();

    // TODO: Add tests for LM_HookCodeEx and LM_UnhookCodeEx

    // separator();

    let inst = LM_Assemble("mov eax, ebx").unwrap();
    println!("[*] Assembled Instruction: {}", inst);

    separator();

    let bytes =
        LM_AssembleEx("push ebp ; mov ebp, esp; mov esp, ebp; pop ebp; ret", 32, 0).unwrap();
    println!("[*] Assembled Instructions: {:#x?}", bytes);

    separator();

    let inst = LM_Disassemble(some_function_addr).unwrap();
    println!("[*] Disassembled Instruction: {}", inst);

    separator();

    let insts =
        LM_DisassembleEx(some_function_addr, LM_BITS, 0x100, 5, some_function_addr).unwrap();
    println!("[*] Disassembled Instructions:");
    for inst in insts {
        println!("{}", inst);
    }

    separator();

    let minsize = 0x5;
    let alignedsize = LM_CodeLength(some_function_addr, minsize).unwrap();
    println!(
        "[*] Aligned Size (minimum: {:#x}): {:#x}",
        minsize, alignedsize
    );

    separator();

    // TODO: Add tests for LM_CodeLengthEx

    // separator();

    println!("[*] VMT Hooking");

    let some_object = SomeClass::new();
    let mut some_object_vmt = lm_vmt_t::new(&some_object as *const SomeClass as *mut lm_address_t);
    some_object_vmt.hook(0, hk_some_function as lm_address_t);

    println!(
        "[*] Original VMT Function: {:#x}",
        some_object_vmt.get_original(0).unwrap()
    );

    some_object.some_function();
    some_object_vmt.unhook(0);

    // let consume_vmt = |_vmt : lm_vmt_t| {};
    // consume_vmt(some_object_vmt);

    println!();
    println!("[*] Unhooked");
    println!();

    some_object.some_function();

    separator();
}

fn main() {
    unsafe {
        test();
    }
}
