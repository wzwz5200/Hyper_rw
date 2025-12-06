#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <algorithm>
#include <type_traits>

#include "HyperCall/call.h"

// 页大小（假定4KB）
constexpr uint64_t PAGE_SIZE = 0x1000;
constexpr uint64_t PAGE_MASK = PAGE_SIZE - 1;

class GuestMemory
{
public:
    explicit GuestMemory(uint64_t default_cr3 = 0) : m_default_cr3(default_cr3) {}

    uint64_t default_cr3() const { return m_default_cr3; }
    void set_default_cr3(uint64_t cr3) { m_default_cr3 = cr3; }

    // ------------------- 物理读写 -------------------
    size_t ReadPhysical(uint64_t phys_addr, void* buffer, size_t size)
    {
        if (!buffer || size == 0) return 0;
        uint64_t ret = hypercall::read_guest_physical_memory(buffer, phys_addr, size);
        return static_cast<size_t>(ret);
    }

    size_t WritePhysical(uint64_t phys_addr, const void* buffer, size_t size)
    {
        if (!buffer || size == 0) return 0;
        uint64_t ret = hypercall::write_guest_physical_memory((void*)buffer, phys_addr, size);
        return static_cast<size_t>(ret);
    }

    // ------------------- 虚拟读写 -------------------
    size_t ReadVirtual(uint64_t guest_va, void* buffer, size_t size, uint64_t target_cr3 = 0)
    {
        if (!buffer || size == 0) return 0;
        uint64_t cr3 = resolve_cr3(target_cr3);
        if (cr3 == 0) return 0;

        uint8_t* out = reinterpret_cast<uint8_t*>(buffer);
        size_t total_read = 0;

        while (total_read < size)
        {
            uint64_t cur_va = guest_va + total_read;
            uint64_t phys = hypercall::translate_guest_virtual_address(cur_va, cr3);
            if (phys == 0) break; // 翻译失败

            size_t page_offset = cur_va & PAGE_MASK;
            size_t to_read = std::min<size_t>(size - total_read, PAGE_SIZE - page_offset);

            size_t got = ReadPhysical(phys, out + total_read, to_read);
            total_read += got;

            if (got != to_read) break;
        }

        return total_read;
    }

    size_t WriteVirtual(uint64_t guest_va, const void* buffer, size_t size, uint64_t target_cr3 = 0)
    {
        if (!buffer || size == 0) return 0;
        uint64_t cr3 = resolve_cr3(target_cr3);
        if (cr3 == 0) return 0;

        const uint8_t* in = reinterpret_cast<const uint8_t*>(buffer);
        size_t total_written = 0;

        while (total_written < size)
        {
            uint64_t cur_va = guest_va + total_written;
            uint64_t phys = hypercall::translate_guest_virtual_address(cur_va, cr3);
            if (phys == 0) break; // 翻译失败

            size_t page_offset = cur_va & PAGE_MASK;
            size_t to_write = std::min<size_t>(size - total_written, PAGE_SIZE - page_offset);

            size_t wrote = WritePhysical(phys, in + total_written, to_write);
            total_written += wrote;

            if (wrote != to_write) break;
        }

        return total_written;
    }

    // ------------------- 模板类型读写 -------------------
    template<typename T>
    bool ReadValue(uint64_t guest_va, T& out_value, uint64_t target_cr3 = 0)
    {
        static_assert(!std::is_pointer<T>::value, "ReadValue<T> 不接受指针类型");

        uint8_t buf[sizeof(T)] = { 0 };
        size_t got = ReadVirtual(guest_va, buf, sizeof(T), target_cr3);
        if (got != sizeof(T))
        {
            out_value = 0;
            return false;
        }

        out_value = 0;
        for (size_t i = 0; i < sizeof(T); ++i)
            out_value |= static_cast<T>(buf[i]) << (i * 8); // 小端组装

        return true;
    }

    template<typename T>
    bool WriteValue(uint64_t guest_va, const T& value, uint64_t target_cr3 = 0)
    {
        static_assert(!std::is_pointer<T>::value, "WriteValue<T> 不接受指针类型");

        uint8_t buf[sizeof(T)];
        for (size_t i = 0; i < sizeof(T); ++i)
            buf[i] = (value >> (i * 8)) & 0xFF;

        return WriteVirtual(guest_va, buf, sizeof(T), target_cr3) == sizeof(T);
    }

    // ------------------- 批量块读写 -------------------
    bool ReadAll(uint64_t guest_va, void* buffer, size_t size, uint64_t target_cr3 = 0)
    {
        return ReadVirtual(guest_va, buffer, size, target_cr3) == size;
    }

    bool WriteAll(uint64_t guest_va, const void* buffer, size_t size, uint64_t target_cr3 = 0)
    {
        return WriteVirtual(guest_va, buffer, size, target_cr3) == size;
    }

private:
    uint64_t m_default_cr3{ 0 };

    uint64_t resolve_cr3(uint64_t target_cr3)
    {
        return (target_cr3 != 0) ? target_cr3 : m_default_cr3;
    }
};
