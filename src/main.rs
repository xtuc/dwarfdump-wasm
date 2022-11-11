use std::env;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::process;

mod dwarfdump;

use dwarfdump::*;
type BoxError = Box<dyn std::error::Error>;

fn print_usage(opts: &getopts::Options) -> ! {
    let brief = format!("Usage: {} <options> <file>", env::args().next().unwrap());
    write!(&mut io::stderr(), "{}", opts.usage(&brief)).ok();
    process::exit(1);
}

fn main() -> std::result::Result<(), BoxError> {
    let mut opts = getopts::Options::new();
    opts.optflag(
        "",
        "eh-frame",
        "print .eh-frame exception handling frame information",
    );
    opts.optflag("G", "", "show global die offsets");
    opts.optflag("i", "", "print .debug_info and .debug_types sections");
    opts.optflag("l", "", "print .debug_line section");
    opts.optflag("p", "", "print .debug_pubnames section");
    opts.optflag("r", "", "print .debug_aranges section");
    opts.optflag("y", "", "print .debug_pubtypes section");
    opts.optflag(
        "",
        "dwo",
        "print the .dwo versions of the selected sections",
    );
    opts.optflag(
        "",
        "dwp",
        "print the .dwp versions of the selected sections",
    );
    opts.optopt(
        "",
        "dwo-parent",
        "use the specified file as the parent of the dwo or dwp (e.g. for .debug_addr)",
        "library path",
    );
    opts.optflag("", "raw", "print raw data values");
    opts.optopt(
        "u",
        "match-units",
        "print compilation units whose output matches a regex",
        "REGEX",
    );
    opts.optopt("", "sup", "path to supplementary object file", "PATH");

    let matches = match opts.parse(env::args().skip(1)) {
        Ok(m) => m,
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}\n", e).ok();
            print_usage(&opts);
        }
    };
    if matches.free.is_empty() {
        print_usage(&opts);
    }

    let mut all = true;
    let mut flags = Flags::default();
    if matches.opt_present("G") {
        flags.goff = true;
    }
    if matches.opt_present("i") {
        flags.info = true;
        all = false;
    }
    if matches.opt_present("l") {
        flags.line = true;
        all = false;
    }
    if matches.opt_present("p") {
        flags.pubnames = true;
        all = false;
    }
    if matches.opt_present("y") {
        flags.pubtypes = true;
        all = false;
    }
    if matches.opt_present("r") {
        flags.aranges = true;
        all = false;
    }
    if matches.opt_present("dwo") {
        flags.dwo = true;
    }
    if matches.opt_present("dwp") {
        flags.dwp = true;
    }
    if matches.opt_present("raw") {
        flags.raw = true;
    }
    if all {
        // .eh_frame is excluded even when printing all information.
        // cosmetic flags like -G must be set explicitly too.
        flags.info = true;
        flags.line = true;
        flags.pubnames = true;
        flags.pubtypes = true;
        flags.aranges = true;
    }
    flags.match_units = None;
    // flags.match_units = if let Some(r) = matches.opt_str("u") {
    //     match Regex::new(&r) {
    //         Ok(r) => Some(r),
    //         Err(e) => {
    //             eprintln!("Invalid regular expression {}: {}", r, e);
    //             process::exit(1);
    //         }
    //     }
    // } else {
    //     None
    // };

    // let arena_mmap = Arena::new();
    // let load_file = |path| {
    //     let file = match fs::File::open(&path) {
    //         Ok(file) => file,
    //         Err(err) => {
    //             eprintln!("Failed to open file '{}': {}", path, err);
    //             process::exit(1);
    //         }
    //     };
    //     let mmap = match unsafe { memmap2::Mmap::map(&file) } {
    //         Ok(mmap) => mmap,
    //         Err(err) => {
    //             eprintln!("Failed to map file '{}': {}", path, err);
    //             process::exit(1);
    //         }
    //     };
    //     let mmap_ref = (*arena_mmap.alloc(mmap)).borrow();
    //     match object::File::parse(&**mmap_ref) {
    //         Ok(file) => Some(file),
    //         Err(err) => {
    //             eprintln!("Failed to parse file '{}': {}", path, err);
    //             process::exit(1);
    //         }
    //     }
    // };

    // flags.sup = matches.opt_str("sup").and_then(load_file);
    // flags.dwo_parent = matches.opt_str("dwo-parent").and_then(load_file);

    for file_path in &matches.free {
        if matches.free.len() != 1 {
            println!("{}", file_path);
            println!();
        }

        let mut file = File::open(file_path).expect("File not found");
        let mut input = Vec::new();
        file.read_to_end(&mut input)
            .expect("Error while reading file");

        let module = wasm_edit::parser::decode(&input)
            .map_err(|err| format!("failed to parse Wasm module: {}", err))?;
        let module = wasm_edit::traverse::WasmModule::new(&module);

        let endian = gimli::RunTimeEndian::Little;
        let ret = dump_file(&module, endian, &flags);
        match ret {
            Ok(_) => (),
            Err(err) => eprintln!("Failed to dump '{}': {}", file_path, err,),
        }
    }

    Ok(())
}
