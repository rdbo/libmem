use libmem::*;

unsafe fn example() {
    let code_str = "push ebp; mov ebp, esp; mov esp, ebp; pop ebp; ret";
    let code_buf = LM_AssembleEx(code_str, 32, 0xdeadbeef).expect("[*] Failed to Assemble Instructions");
    println!("[*] Machine Code: {:02x?}", code_buf);

    println!("[*] Disassembly of 'code_buf':");
    for inst in LM_DisassembleEx(code_buf.as_ptr() as lm_address_t, 32, code_buf.len(), 0, 0xdeadbeef).expect("[*] Failed to Disassemble 'main'") {
        println!("\t{}", inst);
    }
}

fn main() {
    unsafe {
        example();
    }
}
