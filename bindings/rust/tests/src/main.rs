use libmem::{enum_processes, enum_segments, find_module, find_segment, get_process};

pub fn main() {
    let processes = enum_processes().unwrap();
    println!("{:?}", processes);

    let process = get_process().unwrap();
    println!("{}", process);

    let module = find_module(&process.name).unwrap();
    println!("{}", module);

    let segments = enum_segments().unwrap();
    for segment in segments {
        println!("{}", segment);
    }

    let segment = find_segment(module.base).unwrap();
    println!("{}", segment);
}
