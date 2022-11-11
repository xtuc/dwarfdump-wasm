// Modified from https://github.com/gimli-rs/gimli/blob/master/examples/dwarfdump.rs
// Allow clippy lints when building without clippy.
#![allow(unknown_lints)]

use std::borrow;

use fallible_iterator::FallibleIterator;
use gimli::{UnitHeader, UnitOffset, UnitSectionOffset, UnitType};
use regex::bytes::Regex;
use std::borrow::Cow;
use std::cmp::min;
use std::fmt::{self, Debug};
use std::io;
use std::io::{BufWriter, Write};
use std::iter::Iterator;
use std::mem;
use std::result;
use std::sync::{Condvar, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    GimliError(gimli::Error),
    IoError,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}

fn writeln_error<W: Write, R: Reader>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    err: Error,
    msg: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{}: {}",
        msg,
        match err {
            Error::GimliError(err) => dwarf.format_error(err),
            Error::IoError => "An I/O error occurred while writing.".to_string(),
        }
    )
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::GimliError(err)
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::IoError
    }
}

pub type Result<T> = result::Result<T, Error>;

fn parallel_output<W, II, F>(w: &mut W, max_workers: usize, iter: II, f: F) -> Result<()>
where
    W: Write + Send,
    F: Sync + Fn(II::Item, &mut Vec<u8>) -> Result<()>,
    II: IntoIterator,
    II::IntoIter: Send,
{
    struct ParallelOutputState<I, W> {
        iterator: I,
        current_worker: usize,
        result: Result<()>,
        w: W,
    }

    let state = Mutex::new(ParallelOutputState {
        iterator: iter.into_iter().fuse(),
        current_worker: 0,
        result: Ok(()),
        w,
    });
    let workers = min(max_workers, num_cpus::get());
    let mut condvars = Vec::new();
    for _ in 0..workers {
        condvars.push(Condvar::new());
    }
    {
        let state_ref = &state;
        let f_ref = &f;
        let condvars_ref = &condvars;
        crossbeam::scope(|scope| {
            for i in 0..workers {
                scope.spawn(move |_| {
                    let mut v = Vec::new();
                    let mut lock = state_ref.lock().unwrap();
                    while lock.current_worker != i {
                        lock = condvars_ref[i].wait(lock).unwrap();
                    }
                    loop {
                        let item = if lock.result.is_ok() {
                            lock.iterator.next()
                        } else {
                            None
                        };
                        lock.current_worker = (i + 1) % workers;
                        condvars_ref[lock.current_worker].notify_one();
                        mem::drop(lock);

                        let ret = if let Some(item) = item {
                            v.clear();
                            f_ref(item, &mut v)
                        } else {
                            return;
                        };

                        lock = state_ref.lock().unwrap();
                        while lock.current_worker != i {
                            lock = condvars_ref[i].wait(lock).unwrap();
                        }
                        if lock.result.is_ok() {
                            let ret2 = lock.w.write_all(&v);
                            if ret.is_err() {
                                lock.result = ret;
                            } else {
                                lock.result = ret2.map_err(Error::from);
                            }
                        }
                    }
                });
            }
        })
        .unwrap();
    }
    state.into_inner().unwrap().result
}

trait Reader: gimli::Reader<Offset = usize> + Send + Sync {}

impl<'input, Endian> Reader for gimli::EndianSlice<'input, Endian> where
    Endian: gimli::Endianity + Send + Sync
{
}

#[derive(Default)]
pub(crate) struct Flags {
    pub(crate) goff: bool,
    pub(crate) info: bool,
    pub(crate) line: bool,
    pub(crate) pubnames: bool,
    pub(crate) pubtypes: bool,
    pub(crate) aranges: bool,
    pub(crate) dwo: bool,
    pub(crate) dwp: bool,
    pub(crate) raw: bool,
    pub(crate) match_units: Option<Regex>,
}

pub(crate) fn dump_file(
    module: &wasm_edit::traverse::WasmModule,
    endian: gimli::RunTimeEndian,
    flags: &Flags,
) -> Result<()>
where
{
    // Load a section and return as `Cow<[u8]>`.
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>> {
        if let Some(bytes) = module.get_custom_section(id.name()) {
            Ok(borrow::Cow::from(bytes))
        } else {
            eprintln!("unsupported DWARF section {}", id.name());
            Ok(borrow::Cow::Borrowed(&[][..]))
        }
    };

    // Load all of the sections.
    let dwarf_cow = gimli::Dwarf::load(&load_section)?;

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section: &dyn for<'a> Fn(
        &'a borrow::Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
        &|section| gimli::EndianSlice::new(&*section, endian);

    // Create `EndianSlice`s for all of the sections.
    let dwarf = dwarf_cow.borrow(&borrow_section);

    let w = &mut BufWriter::new(io::stdout());

    if flags.info {
        dump_info(w, &dwarf, flags)?;
        dump_types(w, &dwarf, flags)?;
    }
    if flags.line {
        dump_line(w, &dwarf)?;
    }
    if flags.pubnames {
        todo!();
        // let debug_pubnames = &gimli::Section::load(&mut load_section).unwrap();
        // dump_pubnames(w, debug_pubnames, &dwarf.debug_info)?;
    }
    if flags.aranges {
        todo!();
        // let debug_aranges = &gimli::Section::load(&mut load_section).unwrap();
        // dump_aranges(w, debug_aranges)?;
    }
    if flags.pubtypes {
        todo!();
        // let debug_pubtypes = &gimli::Section::load(&mut load_section).unwrap();
        // dump_pubtypes(w, debug_pubtypes, &dwarf.debug_info)?;
    }
    w.flush()?;
    Ok(())
}

fn dump_pointer<W: Write>(w: &mut W, p: gimli::Pointer) -> Result<()> {
    match p {
        gimli::Pointer::Direct(p) => {
            write!(w, "{:#018x}", p)?;
        }
        gimli::Pointer::Indirect(p) => {
            write!(w, "({:#018x})", p)?;
        }
    }
    Ok(())
}

#[allow(clippy::unneeded_field_pattern)]
fn dump_cfi_instructions<R: Reader, W: Write>(
    w: &mut W,
    mut insns: gimli::CallFrameInstructionIter<R>,
    is_initial: bool,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
) -> Result<()> {
    use gimli::CallFrameInstruction::*;

    // TODO: we need to actually evaluate these instructions as we iterate them
    // so we can print the initialized state for CIEs, and each unwind row's
    // registers for FDEs.
    //
    // TODO: We should print DWARF expressions for the CFI instructions that
    // embed DWARF expressions within themselves.

    if !is_initial {
        writeln!(w, "  Instructions:")?;
    }

    loop {
        match insns.next() {
            Err(e) => {
                writeln!(w, "Failed to decode CFI instruction: {}", e)?;
                return Ok(());
            }
            Ok(None) => {
                if is_initial {
                    writeln!(w, "  Instructions: Init State:")?;
                }
                return Ok(());
            }
            Ok(Some(op)) => match op {
                SetLoc { address } => {
                    writeln!(w, "                DW_CFA_set_loc ({:#x})", address)?;
                }
                AdvanceLoc { delta } => {
                    writeln!(w, "                DW_CFA_advance_loc ({})", delta)?;
                }
                DefCfa { register, offset } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa ({}, {})",
                        register_name(register),
                        offset
                    )?;
                }
                DefCfaSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                DefCfaRegister { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_register ({})",
                        register_name(register)
                    )?;
                }
                DefCfaOffset { offset } => {
                    writeln!(w, "                DW_CFA_def_cfa_offset ({})", offset)?;
                }
                DefCfaOffsetSf { factored_offset } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_offset_sf ({})",
                        factored_offset
                    )?;
                }
                DefCfaExpression { expression: _ } => {
                    writeln!(w, "                DW_CFA_def_cfa_expression (...)")?;
                }
                Undefined { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_undefined ({})",
                        register_name(register)
                    )?;
                }
                SameValue { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_same_value ({})",
                        register_name(register)
                    )?;
                }
                Offset {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_offset ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                OffsetExtendedSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_offset_extended_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                ValOffset {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_offset ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                ValOffsetSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_offset_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                Register {
                    dest_register,
                    src_register,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_register ({}, {})",
                        register_name(dest_register),
                        register_name(src_register)
                    )?;
                }
                Expression {
                    register,
                    expression: _,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_expression ({}, ...)",
                        register_name(register)
                    )?;
                }
                ValExpression {
                    register,
                    expression: _,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_expression ({}, ...)",
                        register_name(register)
                    )?;
                }
                Restore { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_restore ({})",
                        register_name(register)
                    )?;
                }
                RememberState => {
                    writeln!(w, "                DW_CFA_remember_state")?;
                }
                RestoreState => {
                    writeln!(w, "                DW_CFA_restore_state")?;
                }
                ArgsSize { size } => {
                    writeln!(w, "                DW_CFA_GNU_args_size ({})", size)?;
                }
                Nop => {
                    writeln!(w, "                DW_CFA_nop")?;
                }
            },
        }
    }
}

fn dump_info<R: Reader, W: Write + Send>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    flags: &Flags,
) -> Result<()>
where
    R::Endian: Send + Sync,
{
    writeln!(w, "\n.debug_info")?;

    let units = match dwarf.units().collect::<Vec<_>>() {
        Ok(units) => units,
        Err(err) => {
            writeln_error(
                w,
                dwarf,
                Error::GimliError(err),
                "Failed to read unit headers",
            )?;
            return Ok(());
        }
    };
    let process_unit = |header: UnitHeader<R>, buf: &mut Vec<u8>| -> Result<()> {
        dump_unit(buf, header, dwarf, flags)?;
        if !flags
            .match_units
            .as_ref()
            .map(|r| r.is_match(&buf))
            .unwrap_or(true)
        {
            buf.clear();
        }
        Ok(())
    };
    // Don't use more than 16 cores even if available. No point in soaking hundreds
    // of cores if you happen to have them.
    parallel_output(w, 16, units, process_unit)
}

fn dump_types<R: Reader, W: Write>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    flags: &Flags,
) -> Result<()> {
    writeln!(w, "\n.debug_types")?;

    let mut iter = dwarf.type_units();
    while let Some(header) = iter.next()? {
        dump_unit(w, header, dwarf, flags)?;
    }
    Ok(())
}

fn dump_unit<R: Reader, W: Write>(
    w: &mut W,
    header: UnitHeader<R>,
    dwarf: &gimli::Dwarf<R>,
    flags: &Flags,
) -> Result<()> {
    write!(w, "\nUNIT<")?;
    match header.offset() {
        UnitSectionOffset::DebugInfoOffset(o) => {
            write!(w, ".debug_info+0x{:08x}", o.0)?;
        }
        UnitSectionOffset::DebugTypesOffset(o) => {
            write!(w, ".debug_types+0x{:08x}", o.0)?;
        }
    }
    writeln!(w, ">: length = 0x{:x}, format = {:?}, version = {}, address_size = {}, abbrev_offset = 0x{:x}",
        header.unit_length(),
        header.format(),
        header.version(),
        header.address_size(),
        header.debug_abbrev_offset().0,
    )?;

    match header.type_() {
        UnitType::Compilation | UnitType::Partial => (),
        UnitType::Type {
            type_signature,
            type_offset,
        }
        | UnitType::SplitType {
            type_signature,
            type_offset,
        } => {
            write!(w, "  signature        = ")?;
            dump_type_signature(w, type_signature)?;
            writeln!(w)?;
            writeln!(w, "  type_offset      = 0x{:x}", type_offset.0,)?;
        }
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => {
            write!(w, "  dwo_id           = ")?;
            writeln!(w, "0x{:016x}", dwo_id.0)?;
        }
    }

    let unit = match dwarf.unit(header) {
        Ok(unit) => unit,
        Err(err) => {
            writeln_error(w, dwarf, err.into(), "Failed to parse unit root entry")?;
            return Ok(());
        }
    };

    let entries_result = dump_entries(w, unit, dwarf, flags);
    if let Err(err) = entries_result {
        writeln_error(w, dwarf, err, "Failed to dump entries")?;
    }
    Ok(())
}

fn spaces(buf: &mut String, len: usize) -> &str {
    while buf.len() < len {
        buf.push(' ');
    }
    &buf[..len]
}

// " GOFF=0x{:08x}" adds exactly 16 spaces.
const GOFF_SPACES: usize = 16;

fn write_offset<R: Reader, W: Write>(
    w: &mut W,
    unit: &gimli::Unit<R>,
    offset: gimli::UnitOffset<R::Offset>,
    flags: &Flags,
) -> Result<()> {
    write!(w, "<0x{:08x}", offset.0)?;
    if flags.goff {
        let goff = match offset.to_unit_section_offset(unit) {
            UnitSectionOffset::DebugInfoOffset(o) => o.0,
            UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        write!(w, " GOFF=0x{:08x}", goff)?;
    }
    write!(w, ">")?;
    Ok(())
}

fn dump_entries<R: Reader, W: Write>(
    w: &mut W,
    unit: gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
    flags: &Flags,
) -> Result<()> {
    let mut spaces_buf = String::new();

    let mut entries = unit.entries_raw(None)?;
    while !entries.is_empty() {
        let offset = entries.next_offset();
        let depth = entries.next_depth();
        let abbrev = entries.read_abbreviation()?;

        let mut indent = if depth >= 0 {
            depth as usize * 2 + 2
        } else {
            2
        };
        write!(w, "<{}{}>", if depth < 10 { " " } else { "" }, depth)?;
        write_offset(w, &unit, offset, flags)?;
        writeln!(
            w,
            "{}{}",
            spaces(&mut spaces_buf, indent),
            abbrev.map(|x| x.tag()).unwrap_or(gimli::DW_TAG_null)
        )?;

        indent += 18;
        if flags.goff {
            indent += GOFF_SPACES;
        }

        for spec in abbrev.map(|x| x.attributes()).unwrap_or(&[]) {
            let attr = entries.read_attribute(*spec)?;
            w.write_all(spaces(&mut spaces_buf, indent).as_bytes())?;
            if let Some(n) = attr.name().static_string() {
                let right_padding = 27 - std::cmp::min(27, n.len());
                write!(w, "{}{} ", n, spaces(&mut spaces_buf, right_padding))?;
            } else {
                write!(w, "{:27} ", attr.name())?;
            }
            if flags.raw {
                writeln!(w, "{:?}", attr.raw_value())?;
            } else {
                match dump_attr_value(w, &attr, &unit, dwarf) {
                    Ok(_) => (),
                    Err(err) => writeln_error(w, dwarf, err, "Failed to dump attribute value")?,
                };
            }
        }
    }
    Ok(())
}

fn dump_attr_value<R: Reader, W: Write>(
    w: &mut W,
    attr: &gimli::Attribute<R>,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<()> {
    let value = attr.value();
    match value {
        gimli::AttributeValue::Addr(address) => {
            writeln!(w, "0x{:08x}", address)?;
        }
        gimli::AttributeValue::Block(data) => {
            for byte in data.to_slice()?.iter() {
                write!(w, "{:02x}", byte)?;
            }
            writeln!(w)?;
        }
        gimli::AttributeValue::Data1(_)
        | gimli::AttributeValue::Data2(_)
        | gimli::AttributeValue::Data4(_)
        | gimli::AttributeValue::Data8(_) => {
            if let (Some(udata), Some(sdata)) = (attr.udata_value(), attr.sdata_value()) {
                if sdata >= 0 {
                    writeln!(w, "{}", udata)?;
                } else {
                    writeln!(w, "{} ({})", udata, sdata)?;
                }
            } else {
                writeln!(w, "{:?}", value)?;
            }
        }
        gimli::AttributeValue::Sdata(data) => {
            match attr.name() {
                gimli::DW_AT_data_member_location => {
                    writeln!(w, "{}", data)?;
                }
                _ => {
                    if data >= 0 {
                        writeln!(w, "0x{:08x}", data)?;
                    } else {
                        writeln!(w, "0x{:08x} ({})", data, data)?;
                    }
                }
            };
        }
        gimli::AttributeValue::Udata(data) => {
            match attr.name() {
                gimli::DW_AT_high_pc => {
                    writeln!(w, "<offset-from-lowpc>{}", data)?;
                }
                gimli::DW_AT_data_member_location => {
                    if let Some(sdata) = attr.sdata_value() {
                        // This is a DW_FORM_data* value.
                        // libdwarf-dwarfdump displays this as signed too.
                        if sdata >= 0 {
                            writeln!(w, "{}", data)?;
                        } else {
                            writeln!(w, "{} ({})", data, sdata)?;
                        }
                    } else {
                        writeln!(w, "{}", data)?;
                    }
                }
                gimli::DW_AT_lower_bound | gimli::DW_AT_upper_bound => {
                    writeln!(w, "{}", data)?;
                }
                _ => {
                    writeln!(w, "0x{:08x}", data)?;
                }
            };
        }
        gimli::AttributeValue::Exprloc(ref data) => {
            if let gimli::AttributeValue::Exprloc(_) = attr.raw_value() {
                write!(w, "len 0x{:04x}: ", data.0.len())?;
                for byte in data.0.to_slice()?.iter() {
                    write!(w, "{:02x}", byte)?;
                }
                write!(w, ": ")?;
            }
            dump_exprloc(w, unit.encoding(), data)?;
            writeln!(w)?;
        }
        gimli::AttributeValue::Flag(true) => {
            writeln!(w, "yes")?;
        }
        gimli::AttributeValue::Flag(false) => {
            writeln!(w, "no")?;
        }
        gimli::AttributeValue::SecOffset(offset) => {
            writeln!(w, "0x{:08x}", offset)?;
        }
        gimli::AttributeValue::DebugAddrBase(base) => {
            writeln!(w, "<.debug_addr+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugAddrIndex(index) => {
            write!(w, "(indirect address, index {:#x}): ", index.0)?;
            let address = dwarf.address(unit, index)?;
            writeln!(w, "0x{:08x}", address)?;
        }
        gimli::AttributeValue::UnitRef(offset) => {
            write!(w, "0x{:08x}", offset.0)?;
            match offset.to_unit_section_offset(unit) {
                UnitSectionOffset::DebugInfoOffset(goff) => {
                    write!(w, "<.debug_info+0x{:08x}>", goff.0)?;
                }
                UnitSectionOffset::DebugTypesOffset(goff) => {
                    write!(w, "<.debug_types+0x{:08x}>", goff.0)?;
                }
            }
            writeln!(w)?;
        }
        gimli::AttributeValue::DebugInfoRef(offset) => {
            writeln!(w, "<.debug_info+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::DebugInfoRefSup(offset) => {
            writeln!(w, "<.debug_info(sup)+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::DebugLineRef(offset) => {
            writeln!(w, "<.debug_line+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::LocationListsRef(offset) => {
            dump_loc_list(w, offset, unit, dwarf)?;
        }
        gimli::AttributeValue::DebugLocListsBase(base) => {
            writeln!(w, "<.debug_loclists+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugLocListsIndex(index) => {
            write!(w, "(indirect location list, index {:#x}): ", index.0)?;
            let offset = dwarf.locations_offset(unit, index)?;
            dump_loc_list(w, offset, unit, dwarf)?;
        }
        gimli::AttributeValue::DebugMacinfoRef(offset) => {
            writeln!(w, "<.debug_macinfo+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::DebugMacroRef(offset) => {
            writeln!(w, "<.debug_macro+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::RangeListsRef(offset) => {
            let offset = dwarf.ranges_offset_from_raw(unit, offset);
            dump_range_list(w, offset, unit, dwarf)?;
        }
        gimli::AttributeValue::DebugRngListsBase(base) => {
            writeln!(w, "<.debug_rnglists+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugRngListsIndex(index) => {
            write!(w, "(indirect range list, index {:#x}): ", index.0)?;
            let offset = dwarf.ranges_offset(unit, index)?;
            dump_range_list(w, offset, unit, dwarf)?;
        }
        gimli::AttributeValue::DebugTypesRef(signature) => {
            dump_type_signature(w, signature)?;
            writeln!(w, " <type signature>")?;
        }
        gimli::AttributeValue::DebugStrRef(offset) => {
            if let Ok(s) = dwarf.debug_str.get_str(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_str+0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::DebugStrRefSup(offset) => {
            if let Some(s) = dwarf
                .sup()
                .and_then(|sup| sup.debug_str.get_str(offset).ok())
            {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_str(sup)+0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::DebugStrOffsetsBase(base) => {
            writeln!(w, "<.debug_str_offsets+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugStrOffsetsIndex(index) => {
            write!(w, "(indirect string, index {:#x}): ", index.0)?;
            let offset = dwarf.debug_str_offsets.get_str_offset(
                unit.encoding().format,
                unit.str_offsets_base,
                index,
            )?;
            if let Ok(s) = dwarf.debug_str.get_str(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_str+0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::DebugLineStrRef(offset) => {
            if let Ok(s) = dwarf.debug_line_str.get_str(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_line_str=0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::String(s) => {
            writeln!(w, "{}", s.to_string_lossy()?)?;
        }
        gimli::AttributeValue::Encoding(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::DecimalSign(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Endianity(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Accessibility(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Visibility(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Virtuality(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Language(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::AddressClass(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::IdentifierCase(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::CallingConvention(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Inline(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Ordering(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::FileIndex(value) => {
            write!(w, "0x{:08x}", value)?;
            dump_file_index(w, value, unit, dwarf)?;
            writeln!(w)?;
        }
        gimli::AttributeValue::DwoId(value) => {
            writeln!(w, "0x{:016x}", value.0)?;
        }
    }

    Ok(())
}

fn dump_type_signature<W: Write>(w: &mut W, signature: gimli::DebugTypeSignature) -> Result<()> {
    write!(w, "0x{:016x}", signature.0)?;
    Ok(())
}

fn dump_file_index<R: Reader, W: Write>(
    w: &mut W,
    file_index: u64,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<()> {
    if file_index == 0 && unit.header.version() <= 4 {
        return Ok(());
    }
    let header = match unit.line_program {
        Some(ref program) => program.header(),
        None => return Ok(()),
    };
    let file = match header.file(file_index) {
        Some(file) => file,
        None => {
            writeln!(w, "Unable to get header for file {}", file_index)?;
            return Ok(());
        }
    };
    write!(w, " ")?;
    if let Some(directory) = file.directory(header) {
        let directory = dwarf.attr_string(unit, directory)?;
        let directory = directory.to_string_lossy()?;
        if file.directory_index() != 0 && !directory.starts_with('/') {
            if let Some(ref comp_dir) = unit.comp_dir {
                write!(w, "{}/", comp_dir.to_string_lossy()?,)?;
            }
        }
        write!(w, "{}/", directory)?;
    }
    write!(
        w,
        "{}",
        dwarf
            .attr_string(unit, file.path_name())?
            .to_string_lossy()?
    )?;
    Ok(())
}

fn dump_exprloc<R: Reader, W: Write>(
    w: &mut W,
    encoding: gimli::Encoding,
    data: &gimli::Expression<R>,
) -> Result<()> {
    let mut pc = data.0.clone();
    let mut space = false;
    while pc.len() != 0 {
        let pc_clone = pc.clone();
        match gimli::Operation::parse(&mut pc, encoding) {
            Ok(op) => {
                if space {
                    write!(w, " ")?;
                } else {
                    space = true;
                }
                dump_op(w, encoding, pc_clone, op)?;
            }
            Err(gimli::Error::InvalidExpression(op)) => {
                writeln!(w, "WARNING: unsupported operation 0x{:02x}", op.0)?;
                return Ok(());
            }
            Err(gimli::Error::UnsupportedRegister(register)) => {
                writeln!(w, "WARNING: unsupported register {}", register)?;
                return Ok(());
            }
            Err(gimli::Error::UnexpectedEof(_)) => {
                writeln!(w, "WARNING: truncated or malformed expression")?;
                return Ok(());
            }
            Err(e) => {
                writeln!(w, "WARNING: unexpected operation parse error: {}", e)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn dump_op<R: Reader, W: Write>(
    w: &mut W,
    encoding: gimli::Encoding,
    mut pc: R,
    op: gimli::Operation<R>,
) -> Result<()> {
    let dwop = gimli::DwOp(pc.read_u8()?);
    write!(w, "{}", dwop)?;
    match op {
        gimli::Operation::Deref {
            base_type, size, ..
        } => {
            if dwop == gimli::DW_OP_deref_size || dwop == gimli::DW_OP_xderef_size {
                write!(w, " {}", size)?;
            }
            if base_type != UnitOffset(0) {
                write!(w, " type 0x{:08x}", base_type.0)?;
            }
        }
        gimli::Operation::Pick { index } => {
            if dwop == gimli::DW_OP_pick {
                write!(w, " {}", index)?;
            }
        }
        gimli::Operation::PlusConstant { value } => {
            write!(w, " {}", value as i64)?;
        }
        gimli::Operation::Bra { target } => {
            write!(w, " {}", target)?;
        }
        gimli::Operation::Skip { target } => {
            write!(w, " {}", target)?;
        }
        gimli::Operation::SignedConstant { value } => match dwop {
            gimli::DW_OP_const1s
            | gimli::DW_OP_const2s
            | gimli::DW_OP_const4s
            | gimli::DW_OP_const8s
            | gimli::DW_OP_consts => {
                write!(w, " {}", value)?;
            }
            _ => {}
        },
        gimli::Operation::UnsignedConstant { value } => match dwop {
            gimli::DW_OP_const1u
            | gimli::DW_OP_const2u
            | gimli::DW_OP_const4u
            | gimli::DW_OP_const8u
            | gimli::DW_OP_constu => {
                write!(w, " {}", value)?;
            }
            _ => {
                // These have the value encoded in the operation, eg DW_OP_lit0.
            }
        },
        gimli::Operation::Register { register } => {
            if dwop == gimli::DW_OP_regx {
                write!(w, " {}", register.0)?;
            }
        }
        gimli::Operation::RegisterOffset {
            register,
            offset,
            base_type,
        } => {
            if dwop >= gimli::DW_OP_breg0 && dwop <= gimli::DW_OP_breg31 {
                write!(w, "{:+}", offset)?;
            } else {
                write!(w, " {}", register.0)?;
                if offset != 0 {
                    write!(w, "{:+}", offset)?;
                }
                if base_type != UnitOffset(0) {
                    write!(w, " type 0x{:08x}", base_type.0)?;
                }
            }
        }
        gimli::Operation::FrameOffset { offset } => {
            write!(w, " {}", offset)?;
        }
        gimli::Operation::Call { offset } => match offset {
            gimli::DieReference::UnitRef(gimli::UnitOffset(offset)) => {
                write!(w, " 0x{:08x}", offset)?;
            }
            gimli::DieReference::DebugInfoRef(gimli::DebugInfoOffset(offset)) => {
                write!(w, " 0x{:08x}", offset)?;
            }
        },
        gimli::Operation::Piece {
            size_in_bits,
            bit_offset: None,
        } => {
            write!(w, " {}", size_in_bits / 8)?;
        }
        gimli::Operation::Piece {
            size_in_bits,
            bit_offset: Some(bit_offset),
        } => {
            write!(w, " 0x{:08x} offset 0x{:08x}", size_in_bits, bit_offset)?;
        }
        gimli::Operation::ImplicitValue { data } => {
            let data = data.to_slice()?;
            write!(w, " 0x{:08x} contents 0x", data.len())?;
            for byte in data.iter() {
                write!(w, "{:02x}", byte)?;
            }
        }
        gimli::Operation::ImplicitPointer { value, byte_offset } => {
            write!(w, " 0x{:08x} {}", value.0, byte_offset)?;
        }
        gimli::Operation::EntryValue { expression } => {
            write!(w, "(")?;
            dump_exprloc(w, encoding, &gimli::Expression(expression))?;
            write!(w, ")")?;
        }
        gimli::Operation::ParameterRef { offset } => {
            write!(w, " 0x{:08x}", offset.0)?;
        }
        gimli::Operation::Address { address } => {
            write!(w, " 0x{:08x}", address)?;
        }
        gimli::Operation::AddressIndex { index } => {
            write!(w, " 0x{:08x}", index.0)?;
        }
        gimli::Operation::ConstantIndex { index } => {
            write!(w, " 0x{:08x}", index.0)?;
        }
        gimli::Operation::TypedLiteral { base_type, value } => {
            write!(w, " type 0x{:08x} contents 0x", base_type.0)?;
            for byte in value.to_slice()?.iter() {
                write!(w, "{:02x}", byte)?;
            }
        }
        gimli::Operation::Convert { base_type } => {
            write!(w, " type 0x{:08x}", base_type.0)?;
        }
        gimli::Operation::Reinterpret { base_type } => {
            write!(w, " type 0x{:08x}", base_type.0)?;
        }
        gimli::Operation::WasmLocal { index } => {
            let wasmop = pc.read_u8()?;
            write!(w, " 0x{:x} 0x{:x}", wasmop, index)?;
        }
        gimli::Operation::WasmGlobal { index } => {
            let wasmop = pc.read_u8()?;
            write!(w, " 0x{:x} 0x{:x}", wasmop, index)?;
        }
        gimli::Operation::WasmStack { index } => {
            let wasmop = pc.read_u8()?;
            write!(w, " 0x{:x} 0x{:x}", wasmop, index)?;
        }
        gimli::Operation::Drop
        | gimli::Operation::Swap
        | gimli::Operation::Rot
        | gimli::Operation::Abs
        | gimli::Operation::And
        | gimli::Operation::Div
        | gimli::Operation::Minus
        | gimli::Operation::Mod
        | gimli::Operation::Mul
        | gimli::Operation::Neg
        | gimli::Operation::Not
        | gimli::Operation::Or
        | gimli::Operation::Plus
        | gimli::Operation::Shl
        | gimli::Operation::Shr
        | gimli::Operation::Shra
        | gimli::Operation::Xor
        | gimli::Operation::Eq
        | gimli::Operation::Ge
        | gimli::Operation::Gt
        | gimli::Operation::Le
        | gimli::Operation::Lt
        | gimli::Operation::Ne
        | gimli::Operation::Nop
        | gimli::Operation::PushObjectAddress
        | gimli::Operation::TLS
        | gimli::Operation::CallFrameCFA
        | gimli::Operation::StackValue => {}
    };
    Ok(())
}

fn dump_range<W: Write>(w: &mut W, range: Option<gimli::Range>) -> Result<()> {
    if let Some(range) = range {
        write!(w, " [0x{:08x}, 0x{:08x}]", range.begin, range.end)?;
    } else {
        write!(w, " [ignored]")?;
    }
    Ok(())
}

fn dump_loc_list<R: Reader, W: Write>(
    w: &mut W,
    offset: gimli::LocationListsOffset<R::Offset>,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<()> {
    let mut locations = dwarf.raw_locations(unit, offset)?;
    writeln!(
        w,
        "<loclist at {}+0x{:08x}>",
        if unit.encoding().version < 5 {
            ".debug_loc"
        } else {
            ".debug_loclists"
        },
        offset.0,
    )?;
    let mut i = 0;
    while let Some(raw) = locations.next()? {
        write!(w, "\t\t\t[{:2}]", i)?;
        i += 1;
        match raw {
            gimli::RawLocListEntry::BaseAddress { addr } => {
                writeln!(w, "<base-address 0x{:08x}>", addr)?;
            }
            gimli::RawLocListEntry::BaseAddressx { addr } => {
                let addr_val = dwarf.address(unit, addr)?;
                writeln!(w, "<base-addressx [{}]0x{:08x}>", addr.0, addr_val)?;
            }
            gimli::RawLocListEntry::StartxEndx {
                begin,
                end,
                ref data,
            } => {
                let begin_val = dwarf.address(unit, begin)?;
                let end_val = dwarf.address(unit, end)?;
                write!(
                    w,
                    "<startx-endx [{}]0x{:08x}, [{}]0x{:08x}>",
                    begin.0, begin_val, end.0, end_val,
                )?;
                let range = gimli::Range {
                    begin: begin_val,
                    end: end_val,
                };
                dump_range(w, Some(range))?;
                dump_exprloc(w, unit.encoding(), data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::StartxLength {
                begin,
                length,
                ref data,
            } => {
                let begin_val = dwarf.address(unit, begin)?;
                write!(
                    w,
                    "<startx-length [{}]0x{:08x}, 0x{:08x}>",
                    begin.0, begin_val, length,
                )?;
                let range = gimli::Range {
                    begin: begin_val,
                    end: begin_val + length,
                };
                dump_range(w, Some(range))?;
                dump_exprloc(w, unit.encoding(), data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::AddressOrOffsetPair {
                begin,
                end,
                ref data,
            }
            | gimli::RawLocListEntry::OffsetPair {
                begin,
                end,
                ref data,
            } => {
                write!(w, "<offset-pair 0x{:08x}, 0x{:08x}>", begin, end)?;
                let range = gimli::Range { begin, end };
                dump_range(w, Some(range))?;
                dump_exprloc(w, unit.encoding(), data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::DefaultLocation { ref data } => {
                write!(w, "<default location>")?;
                dump_exprloc(w, unit.encoding(), data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::StartEnd {
                begin,
                end,
                ref data,
            } => {
                write!(w, "<start-end 0x{:08x}, 0x{:08x}>", begin, end)?;
                let range = gimli::Range { begin, end };
                dump_range(w, Some(range))?;
                dump_exprloc(w, unit.encoding(), data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::StartLength {
                begin,
                length,
                ref data,
            } => {
                write!(w, "<start-length 0x{:08x}, 0x{:08x}>", begin, length)?;
                let range = gimli::Range {
                    begin,
                    end: begin + length,
                };
                dump_range(w, Some(range))?;
                dump_exprloc(w, unit.encoding(), data)?;
                writeln!(w)?;
            }
        };
    }
    Ok(())
}

fn dump_range_list<R: Reader, W: Write>(
    w: &mut W,
    offset: gimli::RangeListsOffset<R::Offset>,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<()> {
    let mut ranges = dwarf.raw_ranges(unit, offset)?;
    writeln!(
        w,
        "<rnglist at {}+0x{:08x}>",
        if unit.encoding().version < 5 {
            ".debug_ranges"
        } else {
            ".debug_rnglists"
        },
        offset.0,
    )?;
    let mut i = 0;
    while let Some(raw) = ranges.next()? {
        write!(w, "\t\t\t[{:2}] ", i)?;
        i += 1;
        match raw {
            gimli::RawRngListEntry::BaseAddress { addr } => {
                writeln!(w, "<new base address 0x{:08x}>", addr)?;
            }
            gimli::RawRngListEntry::BaseAddressx { addr } => {
                let addr_val = dwarf.address(unit, addr)?;
                writeln!(w, "<new base addressx [{}]0x{:08x}>", addr.0, addr_val)?;
            }
            gimli::RawRngListEntry::StartxEndx { begin, end } => {
                let begin_val = dwarf.address(unit, begin)?;
                let end_val = dwarf.address(unit, end)?;
                write!(
                    w,
                    "<startx-endx [{}]0x{:08x}, [{}]0x{:08x}>",
                    begin.0, begin_val, end.0, end_val,
                )?;
                let range = gimli::Range {
                    begin: begin_val,
                    end: end_val,
                };
                dump_range(w, Some(range))?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::StartxLength { begin, length } => {
                let begin_val = dwarf.address(unit, begin)?;
                write!(
                    w,
                    "<startx-length [{}]0x{:08x}, 0x{:08x}>",
                    begin.0, begin_val, length,
                )?;
                let range = gimli::Range {
                    begin: begin_val,
                    end: begin_val + length,
                };
                dump_range(w, Some(range))?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::AddressOrOffsetPair { begin, end }
            | gimli::RawRngListEntry::OffsetPair { begin, end } => {
                write!(w, "<offset-pair 0x{:08x}, 0x{:08x}>", begin, end)?;
                let range = gimli::Range { begin, end };
                dump_range(w, Some(range))?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::StartEnd { begin, end } => {
                write!(w, "<start-end 0x{:08x}, 0x{:08x}>", begin, end)?;
                let range = gimli::Range { begin, end };
                dump_range(w, Some(range))?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::StartLength { begin, length } => {
                write!(w, "<start-length 0x{:08x}, 0x{:08x}>", begin, length)?;
                let range = gimli::Range {
                    begin,
                    end: begin + length,
                };
                dump_range(w, Some(range))?;
                writeln!(w)?;
            }
        };
    }
    Ok(())
}

fn dump_line<R: Reader, W: Write>(w: &mut W, dwarf: &gimli::Dwarf<R>) -> Result<()> {
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        writeln!(
            w,
            "\n.debug_line: line number info for unit at .debug_info offset 0x{:08x}",
            header.offset().as_debug_info_offset().unwrap().0
        )?;
        let unit = match dwarf.unit(header) {
            Ok(unit) => unit,
            Err(err) => {
                writeln_error(
                    w,
                    dwarf,
                    err.into(),
                    "Failed to parse unit root entry for dump_line",
                )?;
                continue;
            }
        };
        match dump_line_program(w, &unit, dwarf) {
            Ok(_) => (),
            Err(Error::IoError) => return Err(Error::IoError),
            Err(err) => writeln_error(w, dwarf, err, "Failed to dump line program")?,
        }
    }
    Ok(())
}

fn dump_line_program<R: Reader, W: Write>(
    w: &mut W,
    unit: &gimli::Unit<R>,
    dwarf: &gimli::Dwarf<R>,
) -> Result<()> {
    if let Some(program) = unit.line_program.clone() {
        {
            let header = program.header();
            writeln!(w)?;
            writeln!(
                w,
                "Offset:                             0x{:x}",
                header.offset().0
            )?;
            writeln!(
                w,
                "Length:                             {}",
                header.unit_length()
            )?;
            writeln!(
                w,
                "DWARF version:                      {}",
                header.version()
            )?;
            writeln!(
                w,
                "Address size:                       {}",
                header.address_size()
            )?;
            writeln!(
                w,
                "Prologue length:                    {}",
                header.header_length()
            )?;
            writeln!(
                w,
                "Minimum instruction length:         {}",
                header.minimum_instruction_length()
            )?;
            writeln!(
                w,
                "Maximum operations per instruction: {}",
                header.maximum_operations_per_instruction()
            )?;
            writeln!(
                w,
                "Default is_stmt:                    {}",
                header.default_is_stmt()
            )?;
            writeln!(
                w,
                "Line base:                          {}",
                header.line_base()
            )?;
            writeln!(
                w,
                "Line range:                         {}",
                header.line_range()
            )?;
            writeln!(
                w,
                "Opcode base:                        {}",
                header.opcode_base()
            )?;

            writeln!(w)?;
            writeln!(w, "Opcodes:")?;
            for (i, length) in header
                .standard_opcode_lengths()
                .to_slice()?
                .iter()
                .enumerate()
            {
                writeln!(w, "  Opcode {} has {} args", i + 1, length)?;
            }

            let base = if header.version() >= 5 { 0 } else { 1 };
            writeln!(w)?;
            writeln!(w, "The Directory Table:")?;
            for (i, dir) in header.include_directories().iter().enumerate() {
                writeln!(
                    w,
                    "  {} {}",
                    base + i,
                    dwarf.attr_string(unit, dir.clone())?.to_string_lossy()?
                )?;
            }

            writeln!(w)?;
            writeln!(w, "The File Name Table")?;
            write!(w, "  Entry\tDir\tTime\tSize")?;
            if header.file_has_md5() {
                write!(w, "\tMD5\t\t\t\t")?;
            }
            writeln!(w, "\tName")?;
            for (i, file) in header.file_names().iter().enumerate() {
                write!(
                    w,
                    "  {}\t{}\t{}\t{}",
                    base + i,
                    file.directory_index(),
                    file.timestamp(),
                    file.size(),
                )?;
                if header.file_has_md5() {
                    let md5 = file.md5();
                    write!(w, "\t")?;
                    for i in 0..16 {
                        write!(w, "{:02X}", md5[i])?;
                    }
                }
                writeln!(
                    w,
                    "\t{}",
                    dwarf
                        .attr_string(unit, file.path_name())?
                        .to_string_lossy()?
                )?;
            }

            writeln!(w)?;
            writeln!(w, "Line Number Instructions:")?;
            let mut instructions = header.instructions();
            while let Some(instruction) = instructions.next_instruction(header)? {
                writeln!(w, "  {}", instruction)?;
            }

            writeln!(w)?;
            writeln!(w, "Line Number Rows:")?;
            writeln!(w, "<pc>        [lno,col]")?;
        }
        let mut rows = program.rows();
        let mut file_index = std::u64::MAX;
        while let Some((header, row)) = rows.next_row()? {
            let line = match row.line() {
                Some(line) => line.get(),
                None => 0,
            };
            let column = match row.column() {
                gimli::ColumnType::Column(column) => column.get(),
                gimli::ColumnType::LeftEdge => 0,
            };
            write!(w, "0x{:08x}  [{:4},{:2}]", row.address(), line, column)?;
            if row.is_stmt() {
                write!(w, " NS")?;
            }
            if row.basic_block() {
                write!(w, " BB")?;
            }
            if row.end_sequence() {
                write!(w, " ET")?;
            }
            if row.prologue_end() {
                write!(w, " PE")?;
            }
            if row.epilogue_begin() {
                write!(w, " EB")?;
            }
            if row.isa() != 0 {
                write!(w, " IS={}", row.isa())?;
            }
            if row.discriminator() != 0 {
                write!(w, " DI={}", row.discriminator())?;
            }
            if file_index != row.file_index() {
                file_index = row.file_index();
                if let Some(file) = row.file(header) {
                    if let Some(directory) = file.directory(header) {
                        write!(
                            w,
                            " uri: \"{}/{}\"",
                            dwarf.attr_string(unit, directory)?.to_string_lossy()?,
                            dwarf
                                .attr_string(unit, file.path_name())?
                                .to_string_lossy()?
                        )?;
                    } else {
                        write!(
                            w,
                            " uri: \"{}\"",
                            dwarf
                                .attr_string(unit, file.path_name())?
                                .to_string_lossy()?
                        )?;
                    }
                }
            }
            writeln!(w)?;
        }
    }
    Ok(())
}

fn dump_pubnames<R: Reader, W: Write>(
    w: &mut W,
    debug_pubnames: &gimli::DebugPubNames<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    writeln!(w, "\n.debug_pubnames")?;

    let mut cu_offset;
    let mut cu_die_offset = gimli::DebugInfoOffset(0);
    let mut prev_cu_offset = None;
    let mut pubnames = debug_pubnames.items();
    while let Some(pubname) = pubnames.next()? {
        cu_offset = pubname.unit_header_offset();
        if Some(cu_offset) != prev_cu_offset {
            let cu = debug_info.header_from_offset(cu_offset)?;
            cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size());
            prev_cu_offset = Some(cu_offset);
        }
        let die_in_cu = pubname.die_offset();
        let die_in_sect = cu_offset.0 + die_in_cu.0;
        writeln!(w,
            "global die-in-sect 0x{:08x}, cu-in-sect 0x{:08x}, die-in-cu 0x{:08x}, cu-header-in-sect 0x{:08x} '{}'",
            die_in_sect,
            cu_die_offset.0,
            die_in_cu.0,
            cu_offset.0,
            pubname.name().to_string_lossy()?
        )?;
    }
    Ok(())
}

fn dump_pubtypes<R: Reader, W: Write>(
    w: &mut W,
    debug_pubtypes: &gimli::DebugPubTypes<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    writeln!(w, "\n.debug_pubtypes")?;

    let mut cu_offset;
    let mut cu_die_offset = gimli::DebugInfoOffset(0);
    let mut prev_cu_offset = None;
    let mut pubtypes = debug_pubtypes.items();
    while let Some(pubtype) = pubtypes.next()? {
        cu_offset = pubtype.unit_header_offset();
        if Some(cu_offset) != prev_cu_offset {
            let cu = debug_info.header_from_offset(cu_offset)?;
            cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size());
            prev_cu_offset = Some(cu_offset);
        }
        let die_in_cu = pubtype.die_offset();
        let die_in_sect = cu_offset.0 + die_in_cu.0;
        writeln!(w,
            "pubtype die-in-sect 0x{:08x}, cu-in-sect 0x{:08x}, die-in-cu 0x{:08x}, cu-header-in-sect 0x{:08x} '{}'",
            die_in_sect,
            cu_die_offset.0,
            die_in_cu.0,
            cu_offset.0,
            pubtype.name().to_string_lossy()?
        )?;
    }
    Ok(())
}

fn dump_aranges<R: Reader, W: Write>(
    w: &mut W,
    debug_aranges: &gimli::DebugAranges<R>,
) -> Result<()> {
    writeln!(w, "\n.debug_aranges")?;

    let mut headers = debug_aranges.headers();
    while let Some(header) = headers.next()? {
        writeln!(
            w,
            "Address Range Header: length = 0x{:08x}, version = 0x{:04x}, cu_offset = 0x{:08x}, addr_size = 0x{:02x}, seg_size = 0x{:02x}",
            header.length(),
            header.encoding().version,
            header.debug_info_offset().0,
            header.encoding().address_size,
            header.segment_size(),
        )?;
        let mut aranges = header.entries();
        while let Some(arange) = aranges.next()? {
            let range = arange.range();
            if let Some(segment) = arange.segment() {
                writeln!(
                    w,
                    "[0x{:016x},  0x{:016x}) segment 0x{:x}",
                    range.begin, range.end, segment
                )?;
            } else {
                writeln!(w, "[0x{:016x},  0x{:016x})", range.begin, range.end)?;
            }
        }
    }
    Ok(())
}
