## Overview

A minimal UEFI bootloader for [SegFaultyLogicOS-kernel](https://github.com/AlianZip/SegFaultyLogicOS-kernel) written in Rust that loads an ELF kernel from the filesystem and hands over control. This bootloader demonstrates basic UEFI protocol usage, memory management, and kernel loading techniques.


## Features

- UEFI-based bootloader written entirely in Rust
- Loads ELF64 kernels from the filesystem
- Graphics Output Protocol (GOP) support for framebuffer information
- Memory management and boot services exit
- ELF parsing and proper segment loading
- Simple error handling and logging

## Requirements

- Rust nightly toolchain
- `x86_64-unknown-uefi` target
- UEFI firmware (QEMU/OVMF or physical hardware)

## How it Works
1. Initialization: Initializes UEFI services and locates the Simple File System protocol
2. Kernel Loading: Opens kernel.elf and reads it into allocated memory
3. Graphics Setup: Retrieves framebuffer information via GOP
4. Memory Management: Exits boot services and finds suitable memory for the kernel
5. ELF Parsing: Parses ELF headers and loads segments into physical memory
6. Handover: Transfers control to the kernel entry point

## Limitations
- Basic error handling (panics on errors)
- Minimal memory validation
- No advanced features like ACPI or SMBIOS passing
- Simple ELF loader without full specification compliance