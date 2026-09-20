use crate::pe::RawSection;
use crate::types::DisassemblyEntry;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

/// Decodes up to `max_instructions` at the given raw slice starting at `base_address`.
pub fn disassemble_bytes(
    code_bytes: &[u8],
    base_address: u64,
    bitness: u32,
    max_instructions: usize,
) -> Vec<DisassemblyEntry> {
    if code_bytes.is_empty() || (bitness != 16 && bitness != 32 && bitness != 64) {
        return Vec::new();
    }

    let mut decoder = Decoder::with_ip(bitness, code_bytes, base_address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(true);

    let mut output = Vec::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() && output.len() < max_instructions {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }

        let ip = instruction.ip();
        let len = instruction.len();
        let start_offset = (ip - base_address) as usize;
        let end_offset = (start_offset + len).min(code_bytes.len());
        let raw_bytes = if start_offset < code_bytes.len() {
            &code_bytes[start_offset..end_offset]
        } else {
            &[]
        };
        let bytes_hex = raw_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let mut output_str = String::new();
        formatter.format(&instruction, &mut output_str);

        let parts: Vec<&str> = output_str.splitn(2, ' ').collect();
        let mnemonic = parts.first().unwrap_or(&"").to_string();
        let op_str = parts.get(1).unwrap_or(&"").trim().to_string();

        output.push(DisassemblyEntry {
            address: ip,
            bytes: bytes_hex,
            mnemonic,
            op_str,
        });
    }

    output
}

/// Resolves the Entry Point within a PE image and disassembles the preamble instructions.
pub fn disassemble_pe_entry_point(
    data: &[u8],
    entry_rva: u32,
    image_base: u64,
    is_64: bool,
    sections: &[RawSection],
    max_instructions: usize,
) -> Vec<DisassemblyEntry> {
    if entry_rva == 0 {
        return Vec::new();
    }

    let offset = match crate::pe::rva_to_offset(entry_rva, sections) {
        Some(off) if off < data.len() => off,
        _ => return Vec::new(),
    };

    let bitness = if is_64 { 64 } else { 32 };
    let code_slice = &data[offset..];
    let vaddr = image_base.wrapping_add(entry_rva as u64);

    disassemble_bytes(code_slice, vaddr, bitness, max_instructions)
}

/// Resolves the Entry Point within an ELF image and disassembles the preamble instructions.
pub fn disassemble_elf_entry_point(
    data: &[u8],
    entry_point: u64,
    is_64: bool,
    arch: &str,
    segments: &[(u64, usize, usize)], // (p_vaddr, p_offset, p_filesz)
    max_instructions: usize,
) -> Vec<DisassemblyEntry> {
    if entry_point == 0 {
        return Vec::new();
    }

    let bitness = if arch.contains("x86_64") || arch.contains("AMD64") {
        64
    } else if arch.contains("x86") || arch.contains("32-bit") {
        32
    } else if is_64 {
        64
    } else {
        32
    };

    let offset = segments.iter().find_map(|&(vaddr, off, filesz)| {
        if entry_point >= vaddr && entry_point < vaddr + filesz as u64 {
            let delta = (entry_point - vaddr) as usize;
            Some(off + delta)
        } else {
            None
        }
    });

    let off = match offset {
        Some(o) if o < data.len() => o,
        _ => return Vec::new(),
    };

    let code_slice = &data[off..];
    disassemble_bytes(code_slice, entry_point, bitness, max_instructions)
}
