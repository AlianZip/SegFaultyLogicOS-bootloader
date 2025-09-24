#![no_main]
#![no_std]

use core::slice::from_raw_parts_mut;

use log::info;
use uefi::boot::{exit_boot_services, memory_map, MemoryType};
use uefi::mem::memory_map::MemoryMap;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::proto::media::file::{File, FileAttribute, FileHandle, FileInfo, FileMode, RegularFile};
use uefi::{
    boot::{
        locate_handle_buffer, open_protocol,
        OpenProtocolAttributes, OpenProtocolParams, SearchType,
    },
    prelude::*,
    proto::{
        loaded_image::LoadedImage,
        media::fs::SimpleFileSystem,
    },
    Identify,
};

use core::mem;
use x86_64::PhysAddr;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const PT_LOAD: u32 = 1;
const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const ELFMAG0: u8 = 0x7F;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';


#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    // let gop_path = locate_handle_buffer(SearchType::ByProtocol(&GopProtocol::GUID));
    let image_handle = boot::image_handle();

    let mut open_params = OpenProtocolParams {
        handle: image_handle,
        agent: image_handle,
        controller: None,
    };
    let loaded_image;

    unsafe {
        loaded_image =
            open_protocol::<LoadedImage>(open_params, OpenProtocolAttributes::GetProtocol)
                .expect("LoadedImage Err");
    };

    let image_device_path = loaded_image.file_path().expect("ICO haven't DevicePath");

    info!("DevicePath loaded");

    let fs_handles = locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
        .expect("there is no device with SimpleFileSystem");

    if fs_handles.is_empty() {
        panic!("there is no device with SimpleFileSystem");
    }
    let fs_device_handle = fs_handles[0];
    info!("find SimpleFileSystem");

    open_params = OpenProtocolParams {
        handle: fs_device_handle,
        agent: image_handle,
        controller: None,
    };
    let mut fs;
    unsafe {
        fs = open_protocol::<SimpleFileSystem>(open_params, OpenProtocolAttributes::Exclusive)
            .expect("failed to open SimpleFileSystem")
    }

    let mut root_dir = fs.open_volume().expect("failed to open root");

    // root_dir.reset_entry_readout();
    // let mut buffer = [0u8; 1024];
    // info!("");
    // info!("");
    // info!("");
    // loop {
    //     match root_dir.read_entry(&mut buffer) {
    //         Ok(Some(entry)) => {
    //             let file_name = entry.file_name();
    //             let is_dir = entry.is_directory();
    //             let file_size = if is_dir {0} else {entry.file_size()};

    //             if is_dir {
    //                 info!("[DIR]  {}", file_name)
    //             } else {
    //                 info!("[FILE] {} ({} bytes)", file_name, file_size);
    //             }
    //         }
    //         Ok(None) => {
    //             break;
    //         },
    //         Err(e) => {
    //             panic!("Error reeding dir: {:?}", e);
    //         }
    //     }
    // }

    let mut kernel_file_handle: FileHandle = root_dir
        .open(
            cstr16!("kernel.elf"),
            FileMode::Read,
            FileAttribute::empty(),
        )
        .expect("failed to open kernel file");

    let mut kernel_regular_file: RegularFile = kernel_file_handle
        .into_regular_file()
        .expect("file of kernel not a file");
    

    let mut kernel_info_buf = [0u8; 128];
    let kernel_info: &mut FileInfo = kernel_regular_file
        .get_info(&mut kernel_info_buf)
        .expect("failed to get kernel information");
    let kernel_file_size = kernel_info.file_size() as usize;
    info!("size of kernel: {} байт", kernel_file_size);

    let kernel_pages_count = (kernel_file_size + 0xFFF) / 0x1000;
    let kernel_load_address: core::ptr::NonNull<u8> = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        kernel_pages_count,
    )
    .expect("failed to allocate memory for the kernel");

    let kernel_load_buffer;
    unsafe {
        kernel_load_buffer = from_raw_parts_mut(kernel_load_address.as_ptr().cast(), kernel_file_size)
    };
    kernel_regular_file
        .read(kernel_load_buffer)
        .expect("Failed to read kernel into memory");

    let gop_handles = locate_handle_buffer(SearchType::ByProtocol(&GraphicsOutput::GUID))
        .expect("could not find GOP descriptors");
    if gop_handles.is_empty() {
        panic!("could not find GOP descriptors");
    }

    let gop_handle = gop_handles[0];
    open_params = OpenProtocolParams {
        handle: gop_handle,
        agent: image_handle,
        controller: None,
    };
    let mut gop;
    unsafe {
        gop = open_protocol::<GraphicsOutput>(
            open_params,
            OpenProtocolAttributes::GetProtocol,
        )
        .expect("can't open GraphicsOutput");
    }
    

    let mode_info = gop.current_mode_info();
    let mut fb_base = gop.frame_buffer();
    let resolution = mode_info.resolution();
    info!(
        "framebuffer: {}x{}, addr 0x{:x}",
        resolution.0, resolution.1, fb_base.as_mut_ptr() as usize
    );


    let memory_map_owned = memory_map(MemoryType::LOADER_DATA)
        .expect("failed to retrieve memory card");
    let map_key = memory_map_owned.key();
    
    info!("retrieve memory card");

    let memory_map_owned;
    unsafe {
        memory_map_owned = exit_boot_services(None)
    }

    info!("exit boot services");
    
    let mut kernel_phys_addr: Option<u64> = None;
    const KERNEL_MIN_SIZE: u64 = 2 * 1024 * 1024; //2 mb

    for descriptor in memory_map_owned.entries() {
        if descriptor.ty == MemoryType::CONVENTIONAL {
            let start = descriptor.phys_start;
            let size = descriptor.page_count * 4096;

            if size >= KERNEL_MIN_SIZE && start >= 0x100000 {
                kernel_phys_addr = Some(start);
                info!("physical address selected for the kernel: 0x{:x}", start);
                break;
            }
        }
    }

    let kernel_phys_addr = kernel_phys_addr.expect("no suitable memory region found");


    info!("parsing ELF-header...");
    let elf_buffer = kernel_load_address.as_ptr();
    let elf_header = unsafe { &*(elf_buffer as *const Elf64Ehdr) };

    if elf_header.e_ident[EI_MAG0] != ELFMAG0 ||
       elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
       elf_header.e_ident[EI_MAG2] != ELFMAG2 ||
       elf_header.e_ident[EI_MAG3] != ELFMAG3 {
        panic!("invalid ELF file format");
    }

    let mut kernel_virt_base = u64::MAX;
    let phdrs_ptr = unsafe { elf_buffer.add(elf_header.e_phoff as usize) as *const Elf64Phdr };
    for i in 0..elf_header.e_phnum {
        let phdr = unsafe { &*phdrs_ptr.add(i as usize) };
        if phdr.p_type == PT_LOAD && phdr.p_vaddr < kernel_virt_base {
            kernel_virt_base = phdr.p_vaddr;
        }
    }
    info!("kernel base virtual address (from ELF): 0x{:x}", kernel_virt_base);

    for i in 0..elf_header.e_phnum {
        let phdr = unsafe { &*phdrs_ptr.add(i as usize) };
        if phdr.p_type == PT_LOAD {
            let offset_in_kernel = phdr.p_vaddr - kernel_virt_base;
            let phys_dest_addr = kernel_phys_addr + offset_in_kernel;

            info!("loading segment: vaddr=0x{:x} -> paddr=0x{:x}", phdr.p_vaddr, phys_dest_addr);

            let dest = phys_dest_addr as *mut u8;
            let src = unsafe { elf_buffer.add(phdr.p_offset as usize) };

            if phdr.p_filesz > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(src, dest, phdr.p_filesz as usize);
                }
            }
            if phdr.p_memsz > phdr.p_filesz {
                let bss_start = unsafe { dest.add(phdr.p_filesz as usize) };
                let bss_size = (phdr.p_memsz - phdr.p_filesz) as usize;
                unsafe {
                    core::ptr::write_bytes(bss_start, 0, bss_size);
                }
            }
        }
    }
      


    let entry_phys_addr = (elf_header.e_entry - kernel_virt_base) + kernel_phys_addr;
    info!("transferring control to the kernel by physical address: 0x{:x}", entry_phys_addr);

    let kernel_entry: extern "C" fn() -> ! = 
        unsafe { core::mem::transmute(entry_phys_addr as *const ()) };
    
    kernel_entry();
    unreachable!();
}
