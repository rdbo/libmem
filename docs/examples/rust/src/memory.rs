use libmem::*;

fn main() {
    let some_var : i32 = 10;
    println!("[*] Value of 'some_var': {}", some_var);

    let read_some_var = LM_ReadMemory::<i32>(&some_var as *const i32 as lm_address_t).unwrap();
    println!("[*] Read Value of 'some_var': {}", read_some_var);

    LM_WriteMemory::<i32>(&some_var as *const i32 as lm_address_t, &1337).unwrap();
    println!("[*] Value of 'some_var' after writing: {}", some_var);
}
