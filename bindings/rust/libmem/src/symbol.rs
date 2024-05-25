use std::ffi::{CStr, CString};

use libmem_sys::{lm_bool_t, lm_module_t, lm_symbol_t, lm_void_t, LM_ADDRESS_BAD, LM_TRUE};

use crate::{Address, Module};

pub struct Symbol {
    pub name: String,
    pub address: Address,
}

impl From<lm_symbol_t> for Symbol {
    fn from(raw_symbol: lm_symbol_t) -> Self {
        Symbol {
            name: unsafe { CStr::from_ptr(raw_symbol.name).to_str().unwrap().to_owned() },
            address: raw_symbol.address,
        }
    }
}

unsafe extern "C" fn enum_symbols_callback(
    raw_symbol: *mut lm_symbol_t,
    arg: *mut lm_void_t,
) -> lm_bool_t {
    let symbols = arg as *mut Vec<Symbol>;
    unsafe { (*symbols).push((*raw_symbol).into()) };
    LM_TRUE
}

/// Enumerates the symbols in a module
pub fn enum_symbols(module: &Module) -> Option<Vec<Symbol>> {
    let raw_module: lm_module_t = module.to_owned().into();
    let mut symbols: Vec<Symbol> = Vec::new();

    let result = unsafe {
        libmem_sys::LM_EnumSymbols(
            &raw_module as *const lm_module_t,
            enum_symbols_callback,
            &mut symbols as *mut Vec<Symbol> as *mut lm_void_t,
        )
    };

    (result == LM_TRUE).then_some(symbols)
}

/// Finds a symbol and retrieves its address
pub fn find_symbol_address(module: &Module, symbol_name: &str) -> Option<Address> {
    let raw_module: lm_module_t = module.to_owned().into();
    let raw_symbol_name = CString::new(symbol_name).ok()?;

    let result = unsafe {
        libmem_sys::LM_FindSymbolAddress(
            &raw_module as *const lm_module_t,
            raw_symbol_name.as_ptr(),
        )
    };

    (result != LM_ADDRESS_BAD).then_some(result)
}

/// Demangles a mangled symbol name
pub fn demangle_symbol(symbol_name: &str) -> Option<String> {
    let c_symbol_name = CString::new(symbol_name).ok()?;
    let demangled =
        unsafe { libmem_sys::LM_DemangleSymbol(c_symbol_name.as_ptr(), std::ptr::null_mut(), 0) };

    if !demangled.is_null() {
        let demangled_name = unsafe { CStr::from_ptr(demangled).to_str().unwrap().to_owned() };

        unsafe { libmem_sys::LM_FreeDemangledSymbol(demangled) }

        Some(demangled_name)
    } else {
        None
    }
}

/// Enumerates and demangles the symbols from a module
pub fn enum_symbols_demangled(module: &Module) -> Option<Vec<Symbol>> {
    let raw_module: lm_module_t = module.to_owned().into();
    let mut symbols: Vec<Symbol> = Vec::new();

    let result = unsafe {
        libmem_sys::LM_EnumSymbolsDemangled(
            &raw_module as *const lm_module_t,
            enum_symbols_callback,
            &mut symbols as *mut Vec<Symbol> as *mut lm_void_t,
        )
    };

    (result == LM_TRUE).then_some(symbols)
}

/// Finds a demangled symbol and retrieves its address
pub fn find_symbol_address_demangled(
    module: &Module,
    demangled_symbol_name: &str,
) -> Option<Address> {
    let raw_module: lm_module_t = module.to_owned().into();
    let raw_symbol_name = CString::new(demangled_symbol_name).ok()?;

    let result = unsafe {
        libmem_sys::LM_FindSymbolAddressDemangled(
            &raw_module as *const lm_module_t,
            raw_symbol_name.as_ptr(),
        )
    };

    (result != LM_ADDRESS_BAD).then_some(result)
}
