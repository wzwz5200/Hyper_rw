#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <inttypes.h>
#include "HyperCall/call.h"


// 简单十六进制转储（每行16字节）
static void hexdump(const void* data, size_t size, uint64_t base_va = 0) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; i += 16) {
        printf("%016" PRIx64 "  ", base_va + i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) printf("%02x ", p[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < size; ++j) {
            uint8_t c = p[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("\n");
    }
}

// 调试读取：打印 translate 结果、物理地址、物理读到的字节，最后尝试按照 32/64/16 位解释
bool DebugReadAndInterpret(uint64_t guest_virtual_address, uint64_t target_cr3, size_t dump_len = 64) {
    if (target_cr3 == 0) {
        printf("[ERR] target_cr3 == 0\n");
        return false;
    }

    printf("[DBG] target_cr3 = 0x%016" PRIx64 "\n", target_cr3);
    printf("[DBG] guest_va    = 0x%016" PRIx64 "\n", guest_virtual_address);

    // 翻译虚拟地址到物理地址（一次翻译）
    uint64_t phys = hypercall::translate_guest_virtual_address(guest_virtual_address, target_cr3);
    printf("[DBG] translate -> phys = 0x%016" PRIx64 "\n", phys);
    if (phys == 0) {
        printf("[ERR] translate_guest_virtual_address returned 0 (未映射或翻译失败)\n");
        return false;
    }

    // 计算页内偏移和从物理页开始读多少字节（保证不跨页）
    const uint64_t PAGE_SIZE = 0x1000;
    uint64_t page_offset = guest_virtual_address & (PAGE_SIZE - 1);
    uint64_t phys_page_base = phys & ~(PAGE_SIZE - 1);
    uint64_t phys_addr = phys_page_base + page_offset;
    size_t can_read = static_cast<size_t>(std::min<uint64_t>(dump_len, PAGE_SIZE - page_offset));

    printf("[DBG] page_offset = 0x%lx, phys_page_base = 0x%016" PRIx64 ", phys_addr = 0x%016" PRIx64 ", can_read=%zu\n",
        page_offset, phys_page_base, phys_addr, can_read);

    std::vector<uint8_t> buf(can_read);
    uint64_t read = hypercall::read_guest_physical_memory(buf.data(), phys_addr, can_read);
    printf("[DBG] read_guest_physical_memory returned = %" PRIu64 "\n", read);
    if (read == 0) {
        printf("[ERR] 物理读失败或读0字节\n");
        return false;
    }

    // hexdump
    printf("[HEXDUMP] (VA-based offsets shown)\n");
    hexdump(buf.data(), static_cast<size_t>(read), guest_virtual_address & ~(PAGE_SIZE - 1));

    // 解释为常见整型（小端）
    // 小端解释：低地址为低字节
    if (read >= 1)  printf("[INT8 ]  %d\n", (int8_t)buf[0]);
    if (read >= 2)  printf("[UINT16] %u\n", (uint16_t)(buf[0] | (buf[1] << 8)));
    if (read >= 4) {
        uint32_t v32 = (uint32_t)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
        printf("[UINT32] %u (0x%08x)\n", v32, v32);
    }
    if (read >= 8) {
        uint64_t v64 = 0;
        for (int i = 0; i < 8; i++) v64 |= (uint64_t)buf[i] << (8 * i);
        printf("[UINT64] %" PRIu64 " (0x%016" PRIx64 ")\n", v64, v64);
    }

    return true;
}
