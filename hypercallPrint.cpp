#include <Windows.h>
#include <WinHvPlatform.h>

#include <cstdint>
#include <cstdio>

#include <stdio.h>
#include <stdlib.h>

#include "whvp.h"

#define PAGE_SIZE 0x1000
#define ROW_SIZE 4
#define MAX_ROW 64

uint8_t* allocateMemory(const uint32_t size) {
    LPVOID mem = VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL) {
        return NULL;
    }
    return (uint8_t*)VirtualAlloc(mem, size, MEM_COMMIT, PAGE_READWRITE);
}

void printRegs(WHvVCPU* vcpu) {
    WHV_REGISTER_NAME regs[] = {
        WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterEfer,
        WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3, WHvX64RegisterCr4, WHvX64RegisterRsp, WHvX64RegisterRbp, WHvX64RegisterGdtr,
        WHvX64RegisterDr0, WHvX64RegisterDr1, WHvX64RegisterDr2, WHvX64RegisterDr3, WHvX64RegisterDr6, WHvX64RegisterDr7, WHvX64RegisterIdtr,
        WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEs, WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterSs, WHvX64RegisterTr, WHvX64RegisterLdtr,
        WHvX64RegisterRip, WHvX64RegisterRflags,
    };
    WHV_REGISTER_VALUE vals[sizeof(regs) / sizeof(regs[0])];

    WHvVCPUStatus vcpuStatus = vcpu->GetRegisters(regs, sizeof(regs) / sizeof(regs[0]), vals);
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("Failed to retrieve VCPU registers\n");
        return;
    }

    printf("EAX = %08x   EBX = %08x   ECX = %08x   EDX = %08x   ESI = %08x   EDI = %08x  EFER = %08x\n", vals[0].Reg32, vals[1].Reg32, vals[2].Reg32, vals[3].Reg32, vals[4].Reg32, vals[5].Reg32, vals[6].Reg32);
    printf("CR0 = %08x   CR2 = %08x   CR3 = %08x   CR4 = %08x   ESP = %08x   EBP = %08x   GDT = %08x:%04x\n", vals[7].Reg32, vals[8].Reg32, vals[9].Reg32, vals[10].Reg32, vals[11].Reg32, vals[12].Reg32, vals[13].Table.Base, vals[13].Table.Limit);
    printf("DR0 = %08x   DR1 = %08x   DR2 = %08x   DR3 = %08x   DR6 = %08x   DR7 = %08x   IDT = %08x:%04x\n", vals[14].Reg32, vals[15].Reg32, vals[16].Reg32, vals[17].Reg32, vals[18].Reg32, vals[19].Reg32, vals[20].Table.Base, vals[20].Table.Limit);
    printf(" CS = %04x   DS = %04x   ES = %04x   FS = %04x   GS = %04x   SS = %04x   TR = %04x   LDT = %08x:%04x\n", vals[21].Segment.Selector, vals[22].Segment.Selector, vals[23].Segment.Selector, vals[24].Segment.Selector, vals[25].Segment.Selector, vals[26].Segment.Selector, vals[27].Segment.Selector, vals[28].Table.Base, vals[28].Table.Limit);
    printf("EIP = %08x   EFLAGS = %08x\n", vals[29].Reg32, vals[30].Reg32);
}

int print(char* disp_str) {
    size_t length = (strlen(disp_str) % 4 == 0) ? strlen(disp_str) + 1 : strlen(disp_str);

    unsigned char* byte_array = (unsigned char*)malloc(length);

    for (size_t i = 0; i < length; i++) {
        byte_array[i] = (unsigned char)disp_str[i];
    }

    size_t row_count = (length + ROW_SIZE - 1) / ROW_SIZE;
    unsigned char byte_matrix[MAX_ROW][6];
    for (size_t i = 0; i < row_count; i++) {
        byte_matrix[i][0] = '\xb8';
        for (size_t j = 0; j < ROW_SIZE; j++) {
            if (i * ROW_SIZE + j < length) {
                byte_matrix[i][j + 1] = byte_array[i * ROW_SIZE + j];
            }
            else {
                byte_matrix[i][j + 1] = '\x00';
            }
        }
    }

    // Initialize ROM and RAM
    const uint32_t romSize = PAGE_SIZE * 16;  // 64 KiB
    const uint32_t ramSize = PAGE_SIZE * 240; // 960 KiB
    const UINT64 romBase = 0xF0000;
    const UINT64 ramBase = 0x0;

    uint8_t* rom = allocateMemory(romSize);
    if (rom == NULL) {
        printf("Failed to allocate ROM memory: error code %d\n", GetLastError());
        return -1;
    }

    uint8_t* ram = allocateMemory(ramSize);
    if (ram == NULL) {
        printf("Failed to allocate RAM memory: error code %d\n", GetLastError());
        return -1;
    }

    // Fill ROM with HLT instructions
    FillMemory(rom, romSize, 0xf4);

    // Zero out RAM
    ZeroMemory(ram, ramSize);

    {
        uint32_t addr;
#define emit(buf, code) {memcpy(&buf[addr], code, sizeof(code) - 1); addr += sizeof(code) - 1;}

        // --- Start of ROM code ----------------------------------------------------------------------------------------------

        // --- GDT and IDT tables ---------------------------------------------------------------------------------------------

        // GDT table
        addr = 0x0000;
        emit(rom, "\x00\x00\x00\x00\x00\x00\x00\x00"); // [0x0000] GDT entry 0: null
        emit(rom, "\xff\xff\x00\x00\x00\x9b\xcf\x00"); // [0x0008] GDT entry 1: code (full access to 4 GB linear space)
        emit(rom, "\xff\xff\x00\x00\x00\x93\xcf\x00"); // [0x0010] GDT entry 2: data (full access to 4 GB linear space)

        // IDT table (system)
        // All entries are present, 80386 32-bit trap gates, privilege level 0, use selector 0x8 and offset 0x10001005
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0018] Vector 0x00: Divide by zero
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0020] Vector 0x01: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0028] Vector 0x02: Non-maskable interrupt
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0030] Vector 0x03: Breakpoint (INT3)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0038] Vector 0x04: Overflow (INTO)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0040] Vector 0x05: Bounds range exceeded (BOUND)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0048] Vector 0x06: Invalid opcode (UD2)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0050] Vector 0x07: Device not available (WAIT/FWAIT)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0058] Vector 0x08: Double fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0060] Vector 0x09: Coprocessor segment overrun
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0068] Vector 0x0A: Invalid TSS
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0070] Vector 0x0B: Segment not present
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0078] Vector 0x0C: Stack-segment fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0080] Vector 0x0D: General protection fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0088] Vector 0x0E: Page fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0090] Vector 0x0F: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0098] Vector 0x10: x87 FPU error
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a0] Vector 0x11: Alignment check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a8] Vector 0x12: Machine check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b0] Vector 0x13: SIMD Floating-Point Exception
        for (uint8_t i = 0x14; i <= 0x1f; i++) {
            emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b8..0x0110] Vector 0x14..0x1F: Reserved
        }

        // IDT table (user defined)
        // All entries are present, 80386 32-bit trap gates, privilege level 0 and use selector 0x8
        emit(rom, "\x00\x10\x08\x00\x00\x8f\x00\x10"); // [0x0118] Vector 0x20: Just IRET       (offset 0x10001000)
        emit(rom, "\x02\x10\x08\x00\x00\x8f\x00\x10"); // [0x0120] Vector 0x21: HLT, then IRET  (offset 0x10001002)

        // --- 32-bit protected mode ------------------------------------------------------------------------------------------

        // Prepare memory for paging
        // 0x1000 = Page directory
        // 0x2000 = Page table (identity map RAM: 0x000xxxxx)
        // 0x3000 = Page table (identity map ROM: 0x000fxxxx)
        // 0x4000 = Page table (0x10000xxx .. 0x10001xxx -> 0x00005xxx .. 0x00006xxx)
        // 0x5000 = Data area (first dword reads 0xdeadbeef)
        // 0x6000 = Interrupt handler code area
        // 0xe000 = Page table (identity map first page of MMIO: 0xe00000xxx)

        // Load segment registers
        addr = 0xff00 - (8 * (row_count - 1));
        emit(rom, "\x33\xc0");                         // [0xfef0] xor    eax, eax

        emit(rom, "\xb0\x10");                         // [0xfef2] mov     al, 0x10
        emit(rom, "\x8e\xd8");                         // [0xfef4] mov     ds, eax
        emit(rom, "\x8e\xc0");                         // [0xfef6] mov     es, eax
        emit(rom, "\x8e\xd0");                         // [0xfef8] mov     ss, eax

        // Clear page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xfefa] mov    edi, 0x1000
        emit(rom, "\xb9\x00\x10\x00\x00");             // [0xfeff] mov    ecx, 0x1000
        emit(rom, "\x31\xc0");                         // [0xff04] xor    eax, eax
        emit(rom, "\xf3\xab");                         // [0xff06] rep    stosd

        // Write disp_str at physical memory address 0x5000

        emit(rom, "\xbf\x00\x50\x00\x00");             // [0xff08] mov    edi, 0x5000

        emit(rom, byte_matrix[0]);
        emit(rom, "\x89\x07");

        for (int i = 1; i < row_count; i++) {
            emit(rom, byte_matrix[i]);
            unsigned char tmp[4];
            tmp[0] = '\x89';
            tmp[1] = '\x47';
            tmp[2] = (unsigned char)4 * i;
            emit(rom, tmp);
        }

        // Identity map the RAM to 0x00000000
        unsigned char offset = 4 * row_count - 1;
        unsigned char tmp[6];
        tmp[0] = '\xb8';
        tmp[1] = offset;
        tmp[2] = '\x00';
        tmp[3] = '\x00';
        tmp[4] = '\x00';
        emit(rom, "\xb9\x00\x01\x00\x00");             // [0xff24] mov    ecx, 0xf0
        emit(rom, "\xbf\x00\x20\x00\x00");             // [0xff29] mov    edi, 0x2000
        emit(rom, tmp);                                // [0xff2e] mov    eax, tmp
        // aLoop:
        emit(rom, "\xab");                             // [0xff33] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff34] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff39] loop   aLoop

        // Identity map the ROM
        emit(rom, "\xb9\x10\x00\x00\x00");             // [0xff3b] mov    ecx, 0x10
        emit(rom, "\xbf\xc0\x3f\x00\x00");             // [0xff40] mov    edi, 0x3fc0
        emit(rom, "\xb8\x03\x00\x0f\x00");             // [0xff45] mov    eax, 0xf0003
        // bLoop:
        emit(rom, "\xab");                             // [0xff4a] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff4b] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff50] loop   bLoop

        // Map physical address 0x5000 to virtual address 0x10000000
        tmp[2] = '\x50';
        emit(rom, "\xbf\x00\x40\x00\x00");             // [0xff52] mov    edi, 0x4000
        emit(rom, tmp);                                // [0xff57] mov    eax, tmp
        emit(rom, "\x89\x07");                         // [0xff5c] mov    [edi], eax

        // Map physical address 0x6000 to virtual address 0x10001000
        emit(rom, "\xbf\x04\x40\x00\x00");             // [0xff5e] mov    edi, 0x4004
        emit(rom, "\xb8\x03\x60\x00\x00");             // [0xff63] mov    eax, 0x6003
        emit(rom, "\x89\x07");                         // [0xff68] mov    [edi], eax

        // Map physical address 0xe0000000 to virtual address 0xe0000000 (for MMIO)
        emit(rom, "\xbf\x00\xe0\x00\x00");             // [0xff6a] mov    edi, 0xe000
        emit(rom, "\xb8\x03\x00\x00\xe0");             // [0xff6f] mov    eax, 0xe0000003
        emit(rom, "\x89\x07");                         // [0xff74] mov    [edi], eax

        // Add page tables into page directory
        tmp[2] = '\x40';
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff76] mov    edi, 0x1000
        emit(rom, "\xb8\x03\x20\x00\x00");             // [0xff7b] mov    eax, 0x2003
        emit(rom, "\x89\x07");                         // [0xff80] mov    [edi], eax
        emit(rom, "\xbf\xfc\x1f\x00\x00");             // [0xff82] mov    edi, 0x1ffc
        emit(rom, "\xb8\x03\x30\x00\x00");             // [0xff87] mov    eax, 0x3003
        emit(rom, "\x89\x07");                         // [0xff8c] mov    [edi], eax
        emit(rom, "\xbf\x00\x11\x00\x00");             // [0xff8e] mov    edi, 0x1100
        emit(rom, tmp);                                // [0xff93] mov    eax, tmp
        emit(rom, "\x89\x07");                         // [0xff98] mov    [edi], eax
        emit(rom, "\xbf\x00\x1e\x00\x00");             // [0xff9a] mov    edi, 0x1e00
        emit(rom, "\xb8\x03\xe0\x00\x00");             // [0xff9f] mov    eax, 0xe003
        emit(rom, "\x89\x07");                         // [0xffa4] mov    [edi], eax

        // Load the page directory register
        emit(rom, "\xb8\x00\x10\x00\x00");             // [0xffa6] mov    eax, 0x1000
        emit(rom, "\x0f\x22\xd8");                     // [0xffab] mov    cr3, eax

        // Enable paging
        emit(rom, "\x0f\x20\xc0");                     // [0xffae] mov    eax, cr0
        emit(rom, "\x0d\x00\x00\x00\x80");             // [0xffb1] or     eax, 0x80000000
        emit(rom, "\x0f\x22\xc0");                     // [0xffb6] mov    cr0, eax

        // Clear EAX
        emit(rom, "\x31\xc0");                         // [0xffb9] xor    eax, eax

        // Load using virtual memory address; EAX = 0xdeadbeef
        emit(rom, "\xbe\x00\x00\x00\x10");             // [0xffbb] mov    esi, 0x10000000
        emit(rom, "\x8b\x06");                         // [0xffc0] mov    eax, [esi]

        // First stop
        emit(rom, "\xf4");                             // [0xffc2] hlt

        // Jump to RAM
        tmp[0] = '\xe9';
        tmp[1] = 0x39 + offset;
        tmp[2] = '\x00';
        tmp[3] = '\xf0';
        tmp[4] = '\x0f';
        emit(rom, tmp);                               // [0xffc3] jmp    tmp
        // .. ends at 0xffc7

// --- 16-bit real mode transition to 32-bit protected mode -----------------------------------------------------------

// Load GDT and IDT tables
        addr = 0xffd0;
        emit(rom, "\x66\x2e\x0f\x01\x16\xf2\xff");     // [0xffd0] lgdt   [cs:0xfff2]
        emit(rom, "\x66\x2e\x0f\x01\x1e\xf8\xff");     // [0xffd7] lidt   [cs:0xfff8]

        // Enter protected mode
        emit(rom, "\x0f\x20\xc0");                     // [0xffde] mov    eax, cr0
        emit(rom, "\x0c\x01");                         // [0xffe1] or      al, 1
        emit(rom, "\x0f\x22\xc0");                     // [0xffe3] mov    cr0, eax

        int _addr = 0xff00 - (8 * (row_count - 1));
        unsigned char tmp2[9];
        tmp2[0] = '\x66';
        tmp2[1] = '\xea';
        tmp2[2] = (unsigned char)_addr & 0xFF;
        tmp2[3] = (unsigned char)(_addr >> 8) & 0xFF;
        tmp2[4] = '\x0f';
        tmp2[5] = '\x00';
        tmp2[6] = '\x08';
        tmp2[7] = '\x00';

        emit(rom, tmp2); // [0xffe6] jmp    dword 0x8:0x000ffef0
        emit(rom, "\xf4");                             // [0xffef] hlt

        // --- 16-bit real mode start -----------------------------------------------------------------------------------------

        // Jump to initialization code and define GDT/IDT table pointer
        addr = 0xfff0;
        emit(rom, "\xeb\xde");                         // [0xfff0] jmp    short 0x1d0
        emit(rom, "\x18\x00\x00\x00\x0f\x00");         // [0xfff2] GDT pointer: 0x000f0000:0x0018
        emit(rom, "\x10\x01\x18\x00\x0f\x00");         // [0xfff8] IDT pointer: 0x000f0018:0x0110
        // There's room for two bytes at the end, so let's fill it up with HLTs
        emit(rom, "\xf4");                             // [0xfffe] hlt
        emit(rom, "\xf4");                             // [0xffff] hlt

        // --- End of ROM code ------------------------------------------------------------------------------------------------

        // --- Start of RAM code ----------------------------------------------------------------------------------------------
        addr = 0x5000 + 4 * row_count;
        // Note that these addresses are mapped to virtual addresses 0x10000000 through 0x10000fff

        // Write to virtual memory
        emit(ram, "\xbf\x00\x00\x00\x10");             // [0x5009] mov    edi, 0x10000000
        emit(ram, "\x8b\x07");                         // [0x5010] mov    [edi], eax
        emit(ram, "\x0f\x01\xd9");                     // [0x5012] vmcall

#undef emit
    }

    // ----- Hypervisor platform initialization -------------------------------------------------------------------------------

    // Initialize the hypervisor platform
    WinHvPlatform whvp;
    if (!whvp.IsPresent()) {
        printf("Hyper-V platform absent\n");
        return -1;
    }

    // Check CPU vendor
    WHV_CAPABILITY cap;
    WHvStatus status = whvp.GetCapability(WHvCapabilityCodeProcessorVendor, &cap);

    // Create a partition
    WHvPartition* partition;
    WHvPartitionStatus partStatus = whvp.CreatePartition(&partition);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to create partition\n");
        return -1;
    }

    // Give one processor to the partition
    WHV_PARTITION_PROPERTY partitionProperty;
    partitionProperty.ProcessorCount = 1;
    partStatus = partition->SetProperty(WHvPartitionPropertyCodeProcessorCount, &partitionProperty);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to set processor count to partition\n");
        return -1;
    }

    // Setup the partition
    partStatus = partition->Setup();
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to setup partition\n");
        return -1;
    }

    // Map ROM to the top of the 32-bit address range
    partStatus = partition->MapGpaRange(rom, romBase, romSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to map guest physical address range for ROM\n");
        return -1;
    }

    // Map RAM to the bottom of the 32-bit address range
    partStatus = partition->MapGpaRange(ram, ramBase, ramSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to map guest physical address range for RAM\n");
        return -1;
    }

    // Create a VCPU
    WHvVCPU* vcpu;
    const UINT32 vpIndex = 0;
    WHvVCPUStatus vcpuStatus = partition->CreateVCPU(&vcpu, vpIndex);
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("Failed to create VCPU\n");
        return -1;
    }

    // ----- Start of emulation -----------------------------------------------------------------------------------------------

    // The CPU starts in 16-bit real mode.
    // Memory addressing is based on segments and offsets, where a segment is basically a 16-byte offset.

    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("VCPU failed to run\n");
        return -1;
    }

    if (vcpu->ExitContext()->ExitReason == WHvRunVpExitReasonHypercall) {
        char* memValue = (char*)&ram[0x5000];
        printf("%s\n\n", memValue);
    }

    // ----- Cleanup ----------------------------------------------------------------------------------------------------------
    // Free RAM
    if (!VirtualFree(ram, 0, MEM_RELEASE)) {
        printf("Failed to free RAM memory: error code %d\n", GetLastError());
    }

    // Free ROM
    if (!VirtualFree(rom, 0, MEM_RELEASE)) {
        printf("Failed to free ROM memory: error code %d\n", GetLastError());
    }

    return 0;
}

int execute_binary(char *file_name) {
    // Initialize ROM and RAM
    const uint32_t romSize = PAGE_SIZE * 16;  // 64 KiB
    const uint32_t ramSize = PAGE_SIZE * 240; // 960 KiB
    const UINT64 romBase = 0xF0000;
    const UINT64 ramBase = 0x0;

    // --- Setting for CPU1 ----------------------------------------------------------
    uint8_t* rom = allocateMemory(romSize);
    if (rom == NULL) {
        printf("Failed to allocate ROM memory: error code %d\n", GetLastError());
        return -1;
    }
    uint8_t* ram = allocateMemory(ramSize);
    if (ram == NULL) {
        printf("Failed to allocate RAM memory: error code %d\n", GetLastError());
        return -1;
    }
    // Fill ROM with HLT instructions
    FillMemory(rom, romSize, 0xf4);
    // Zero out RAM
    ZeroMemory(ram, ramSize);


    FILE* file;
    fopen_s(&file, file_name, "r");
    if (!file) {
        perror("Cannot open the file");
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(size);

    if (!buffer) {
        perror("Cannot allocate memory");
        fclose(file);
    }

    fread(buffer, 1, size, file);
    fclose(file);

    int hexNumberSize = (size + 1) / (3 * sizeof(char));

    char* token;
    char* ptr;
    unsigned char* hexNumbers = (unsigned char*)malloc(hexNumberSize);
    int index = 0;
    char* next_token1 = NULL;

    token = strtok_s(buffer, " ", &next_token1);
    while (token != NULL) {
        hexNumbers[index] = strtol(token, &ptr, 16);
        index++;

        token = strtok_s(NULL, " ", &next_token1);
    }

    {
        uint32_t addr;
#define emit(buf, code) {memcpy(&buf[addr], code, sizeof(code) - 1); addr += sizeof(code) - 1;}
#define _emit(buf, code, size) {memcpy(&buf[addr], code, size); addr += size - 1;}

        // --- Start of ROM code ----------------------------------------------------------------------------------------------

        // --- GDT and IDT tables ---------------------------------------------------------------------------------------------

        // GDT table
        addr = 0x0000;
        emit(rom, "\x00\x00\x00\x00\x00\x00\x00\x00"); // [0x0000] GDT entry 0: null
        emit(rom, "\xff\xff\x00\x00\x00\x9b\xcf\x00"); // [0x0008] GDT entry 1: code (full access to 4 GB linear space)
        emit(rom, "\xff\xff\x00\x00\x00\x93\xcf\x00"); // [0x0010] GDT entry 2: data (full access to 4 GB linear space)

        // IDT table (system)
        // All entries are present, 80386 32-bit trap gates, privilege level 0, use selector 0x8 and offset 0x10001005
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0018] Vector 0x00: Divide by zero
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0020] Vector 0x01: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0028] Vector 0x02: Non-maskable interrupt
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0030] Vector 0x03: Breakpoint (INT3)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0038] Vector 0x04: Overflow (INTO)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0040] Vector 0x05: Bounds range exceeded (BOUND)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0048] Vector 0x06: Invalid opcode (UD2)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0050] Vector 0x07: Device not available (WAIT/FWAIT)
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0058] Vector 0x08: Double fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0060] Vector 0x09: Coprocessor segment overrun
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0068] Vector 0x0A: Invalid TSS
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0070] Vector 0x0B: Segment not present
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0078] Vector 0x0C: Stack-segment fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0080] Vector 0x0D: General protection fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0088] Vector 0x0E: Page fault
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0090] Vector 0x0F: Reserved
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x0098] Vector 0x10: x87 FPU error
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a0] Vector 0x11: Alignment check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00a8] Vector 0x12: Machine check
        emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b0] Vector 0x13: SIMD Floating-Point Exception
        for (uint8_t i = 0x14; i <= 0x1f; i++) {
            emit(rom, "\x05\x10\x08\x00\x00\x8f\x00\x10"); // [0x00b8..0x0110] Vector 0x14..0x1F: Reserved
        }

        // IDT table (user defined)
        // All entries are present, 80386 32-bit trap gates, privilege level 0 and use selector 0x8
        emit(rom, "\x00\x10\x08\x00\x00\x8f\x00\x10"); // [0x0118] Vector 0x20: Just IRET       (offset 0x10001000)
        emit(rom, "\x02\x10\x08\x00\x00\x8f\x00\x10"); // [0x0120] Vector 0x21: HLT, then IRET  (offset 0x10001002)

        // --- 32-bit protected mode ------------------------------------------------------------------------------------------

        // Prepare memory for paging
        // 0x1000 = Page directory
        // 0x2000 = Page table (identity map RAM: 0x000xxxxx)
        // 0x3000 = Page table (identity map ROM: 0x000fxxxx)
        // 0x4000 = Page table (0x10000xxx .. 0x10001xxx -> 0x00005xxx .. 0x00006xxx)
        // 0x5000 = Data area (first dword reads 0xdeadbeef)
        // 0x6000 = Interrupt handler code area
        // 0xe000 = Page table (identity map first page of MMIO: 0xe00000xxx)

        // Load segment registers
        addr = 0xff00;

        emit(rom, "\x33\xc0");                         // [0xff00] xor    eax, eax

        emit(rom, "\xb0\x10");                         // [0xff02] mov     al, 0x10
        emit(rom, "\x8e\xd8");                         // [0xff04] mov     ds, eax
        emit(rom, "\x8e\xc0");                         // [0xff06] mov     es, eax
        emit(rom, "\x8e\xd0");                         // [0xff08] mov     ss, eax

        // Clear page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff0a] mov    edi, 0x1000
        emit(rom, "\xb9\x00\x10\x00\x00");             // [0xff0f] mov    ecx, 0x1000
        emit(rom, "\x31\xc0");                         // [0xff14] xor    eax, eax
        emit(rom, "\xf3\xab");                         // [0xff16] rep    stosd

        // Write 0xdeadbeef at physical memory address 0x5000
        emit(rom, "\xbf\x00\x50\x00\x00");             // [0xff18] mov    edi, 0x5000
        emit(rom, "\xb8\xef\xbe\xad\xde");             // [0xff1d] mov    eax, 0xdeadbeef
        emit(rom, "\x89\x07");                         // [0xff22] mov    [edi], eax

        // Identity map the RAM to 0x00000000
        emit(rom, "\xb9\x00\x01\x00\x00");             // [0xff24] mov    ecx, 0xf0
        emit(rom, "\xbf\x00\x20\x00\x00");             // [0xff29] mov    edi, 0x2000
        emit(rom, "\xb8\x03\x00\x00\x00");             // [0xff2e] mov    eax, 0x0003
        // aLoop:
        emit(rom, "\xab");                             // [0xff33] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff34] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff39] loop   aLoop

        // Identity map the ROM
        emit(rom, "\xb9\x10\x00\x00\x00");             // [0xff3b] mov    ecx, 0x10
        emit(rom, "\xbf\xc0\x3f\x00\x00");             // [0xff40] mov    edi, 0x3fc0
        emit(rom, "\xb8\x03\x00\x0f\x00");             // [0xff45] mov    eax, 0xf0003
        // bLoop:
        emit(rom, "\xab");                             // [0xff4a] stosd
        emit(rom, "\x05\x00\x10\x00\x00");             // [0xff4b] add    eax, 0x1000
        emit(rom, "\xe2\xf8");                         // [0xff50] loop   bLoop

        // Map physical address 0x5000 to virtual address 0x10000000
        emit(rom, "\xbf\x00\x40\x00\x00");             // [0xff52] mov    edi, 0x4000
        emit(rom, "\xb8\x03\x50\x00\x00");             // [0xff57] mov    eax, 0x5003
        emit(rom, "\x89\x07");                         // [0xff5c] mov    [edi], eax

        // Map physical address 0x6000 to virtual address 0x10001000
        emit(rom, "\xbf\x04\x40\x00\x00");             // [0xff5e] mov    edi, 0x4004
        emit(rom, "\xb8\x03\x60\x00\x00");             // [0xff63] mov    eax, 0x6003
        emit(rom, "\x89\x07");                         // [0xff68] mov    [edi], eax

        // Map physical address 0xe0000000 to virtual address 0xe0000000 (for MMIO)
        emit(rom, "\xbf\x00\xe0\x00\x00");             // [0xff6a] mov    edi, 0xe000
        emit(rom, "\xb8\x03\x00\x00\xe0");             // [0xff6f] mov    eax, 0xe0000003
        emit(rom, "\x89\x07");                         // [0xff74] mov    [edi], eax

        // Add page tables into page directory
        emit(rom, "\xbf\x00\x10\x00\x00");             // [0xff76] mov    edi, 0x1000
        emit(rom, "\xb8\x03\x20\x00\x00");             // [0xff7b] mov    eax, 0x2003
        emit(rom, "\x89\x07");                         // [0xff80] mov    [edi], eax
        emit(rom, "\xbf\xfc\x1f\x00\x00");             // [0xff82] mov    edi, 0x1ffc
        emit(rom, "\xb8\x03\x30\x00\x00");             // [0xff87] mov    eax, 0x3003
        emit(rom, "\x89\x07");                         // [0xff8c] mov    [edi], eax
        emit(rom, "\xbf\x00\x11\x00\x00");             // [0xff8e] mov    edi, 0x1100
        emit(rom, "\xb8\x03\x40\x00\x00");             // [0xff93] mov    eax, 0x4003
        emit(rom, "\x89\x07");                         // [0xff98] mov    [edi], eax
        emit(rom, "\xbf\x00\x1e\x00\x00");             // [0xff9a] mov    edi, 0x1e00
        emit(rom, "\xb8\x03\xe0\x00\x00");             // [0xff9f] mov    eax, 0xe003
        emit(rom, "\x89\x07");                         // [0xffa4] mov    [edi], eax

        // Load the page directory register
        emit(rom, "\xb8\x00\x10\x00\x00");             // [0xffa6] mov    eax, 0x1000
        emit(rom, "\x0f\x22\xd8");                     // [0xffab] mov    cr3, eax

        // Enable paging
        emit(rom, "\x0f\x20\xc0");                     // [0xffae] mov    eax, cr0
        emit(rom, "\x0d\x00\x00\x00\x80");             // [0xffb1] or     eax, 0x80000000
        emit(rom, "\x0f\x22\xc0");                     // [0xffb6] mov    cr0, eax

        // Clear EAX
        emit(rom, "\x31\xc0");                         // [0xffb9] xor    eax, eax

        // Load using virtual memory address; EAX = 0xdeadbeef
        emit(rom, "\xbe\x00\x00\x00\x10");             // [0xffbb] mov    esi, 0x10000000
        emit(rom, "\x8b\x06");                         // [0xffc0] mov    eax, [esi]

        // First stop
        emit(rom, "\xf4");                             // [0xffc2] hlt

        // Jump to RAM
        emit(rom, "\xe9\x3c\x00\xf0\x0f");             // [0xffc3] jmp    0x10000004
        // .. ends at 0xffc7

        // --- 16-bit real mode transition to 32-bit protected mode -----------------------------------------------------------

        // Load GDT and IDT tables
        addr = 0xffd0;
        emit(rom, "\x66\x2e\x0f\x01\x16\xf2\xff");     // [0xffd0] lgdt   [cs:0xfff2]
        emit(rom, "\x66\x2e\x0f\x01\x1e\xf8\xff");     // [0xffd7] lidt   [cs:0xfff8]

        // Enter protected mode
        emit(rom, "\x0f\x20\xc0");                     // [0xffde] mov    eax, cr0
        emit(rom, "\x0c\x01");                         // [0xffe1] or      al, 1
        emit(rom, "\x0f\x22\xc0");                     // [0xffe3] mov    cr0, eax

        emit(rom, "\x66\xea\x00\xff\x0f\x00\x08\x00"); // [0xffe6] jmp    dword 0x8:0x000fff00
        emit(rom, "\xf4");                             // [0xffef] hlt

        // --- 16-bit real mode start -----------------------------------------------------------------------------------------

        // Jump to initialization code and define GDT/IDT table pointer
        addr = 0xfff0;
        emit(rom, "\xeb\xde");                         // [0xfff0] jmp    short 0x1d0

        emit(rom, "\x18\x00\x00\x00\x0f\x00");         // [0xfff2] GDT pointer: 0x000f0000:0x0018
        emit(rom, "\x10\x01\x18\x00\x0f\x00");         // [0xfff8] IDT pointer: 0x000f0018:0x0110
        // There's room for two bytes at the end, so let's fill it up with HLTs
        emit(rom, "\xf4");                             // [0xfffe] hlt
        emit(rom, "\xf4");                             // [0xffff] hlt

        // --- End of ROM code ------------------------------------------------------------------------------------------------

        // --- Start of RAM code ----------------------------------------------------------------------------------------------
        addr = 0x5004;
        // Note that these addresses are mapped to virtual addresses 0x10000000 through 0x10000fff

        // Setup a proper stack
        emit(ram, "\x31\xed");                         // [0x5013] xor    ebp, ebp
        emit(ram, "\xbc\x00\x00\x0f\x00");             // [0x5015] mov    esp, 0xf0000

        _emit(ram, hexNumbers, index);
#undef emit
    }

    // ----- Hypervisor platform initialization -------------------------------------------------------------------------------

    // Initialize the hypervisor platform
    WinHvPlatform whvp;
    if (!whvp.IsPresent()) {
        printf("Hyper-V for CPU1 platform absent\n");
    }

    // Check CPU vendor
    WHV_CAPABILITY cap;
    WHvStatus status1 = whvp.GetCapability(WHvCapabilityCodeProcessorVendor, &cap);

    // Create a partition
    WHvPartition* partition;
    WHvPartitionStatus partStatus = whvp.CreatePartition(&partition);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to create partition for CPU\n");
    }

    // Give one processor to the partition
    WHV_PARTITION_PROPERTY partitionProperty;
    partitionProperty.ProcessorCount = 1;
    partStatus = partition->SetProperty(WHvPartitionPropertyCodeProcessorCount, &partitionProperty);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to set processor count to partition for CPU\n");
    }

    // Setup the partition
    partStatus = partition->Setup();
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to setup partition for CPU\n");
    }

    // Map ROM to the top of the 32-bit address range
    partStatus = partition->MapGpaRange(rom, romBase, romSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to map guest physical address range for ROM\n");
    }

    // Map RAM to the bottom of the 32-bit address range
    partStatus = partition->MapGpaRange(ram, ramBase, ramSize, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    if (WHVPS_SUCCESS != partStatus) {
        printf("Failed to map guest physical address range for RAM\n");
    }

    // Create a VCPU
    WHvVCPU* vcpu;
    const UINT32 vpIndex = 0;
    WHvVCPUStatus vcpuStatus = partition->CreateVCPU(&vcpu, vpIndex);
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("Failed to create VCPU\n");
    }

    // ----- Start of emulation -----------------------------------------------------------------------------------------------

    // The CPU starts in 16-bit real mode.
    // Memory addressing is based on segments and offsets, where a segment is basically a 16-byte offset.

    // Run the CPU!
    vcpuStatus = vcpu->Run();
    if (WHVVCPUS_SUCCESS != vcpuStatus) {
        printf("1) VCPU failed to run\n");
    }

    int i = 0;
    while (true) {
        vcpuStatus = vcpu->Run();
        if (WHVVCPUS_SUCCESS != vcpuStatus) {
            printf("2) VCPU failed to run\n");
        }
        if (vcpu->ExitContext()->ExitReason == WHvRunVpExitReasonHypercall) {
            char* memValue = (char*)&ram[0x5000];
            printf("%s\n", memValue);

            // Update Rip
            WHV_REGISTER_NAME reg[] = { WHvX64RegisterRip };
            WHV_REGISTER_VALUE val[sizeof(reg) / sizeof(reg[0])];
            vcpuStatus = vcpu->GetRegisters(reg, sizeof(reg) / sizeof(reg[0]), val);
            if (WHVVCPUS_SUCCESS != vcpuStatus) { return vcpuStatus; }
            val[0].Reg32 = 0x501a + 10*i;
            vcpuStatus = vcpu->SetRegisters(reg, sizeof(reg) / sizeof(reg[0]), val);

            i += 1;
        }
        else {
            if (!VirtualFree(ram, 0, MEM_RELEASE)) {
                printf("Failed to free RAM memory: error code %d\n", GetLastError());
            }

            // Free ROM
            if (!VirtualFree(rom, 0, MEM_RELEASE)) {
                printf("Failed to free ROM memory: error code %d\n", GetLastError());
            }
            return 0;
        }
    }
}

int main() {
    char input_str[256];
    while (true) {
        printf("> ");
        scanf_s("%255s", input_str, sizeof(input_str));
        if (!strcmp(input_str, "quit")) {
            return 0;
        }
        else if (strstr(input_str, "printf") == input_str) {
            char extracted[256];
            int start_index = strchr(input_str, '\"') - input_str + 1;
            int end_index = strrchr(input_str, '\"') - input_str;
            int length = end_index - start_index;
            strncpy_s(extracted, &input_str[start_index], length);
            extracted[length] = '\0';
            print(extracted);
        }
        else if (strstr(input_str, "exec") == input_str) {
            char extracted[256];
            int start_index = strchr(input_str, '\"') - input_str + 1;
            int end_index = strrchr(input_str, '\"') - input_str;
            int length = end_index - start_index;
            strncpy_s(extracted, &input_str[start_index], length);
            extracted[length] = '\0';
            execute_binary(extracted);
        }
    }
    return 0;
}
