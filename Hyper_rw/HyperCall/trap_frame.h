#pragma once
#include <cstdint>

struct trap_frame_t
{
    std::uint64_t rax;
    std::uint64_t rcx;
    std::uint64_t rdx;
    std::uint64_t rbx;
    std::uint64_t rsp;
    std::uint64_t rbp;
    std::uint64_t rsi;
    std::uint64_t rdi;
    std::uint64_t r8;
    std::uint64_t r9;
    std::uint64_t r10;
    std::uint64_t r11;
    std::uint64_t r12;
    std::uint64_t r13;
    std::uint64_t r14;
    std::uint64_t r15;
};

constexpr std::uint64_t trap_frame_log_stack_data_count = 5;

struct trap_frame_log_t : trap_frame_t
{
    std::uint64_t rip;
    std::uint64_t cr3;

    std::uint64_t stack_data[trap_frame_log_stack_data_count];
};

struct nmi_trap_frame_t
{
    std::uint64_t rax;
    std::uint64_t rcx;
    std::uint64_t rdx;
    std::uint64_t rbx;
    std::uint64_t rbp;
    std::uint64_t rsi;
    std::uint64_t rdi;
    std::uint64_t r8;
    std::uint64_t r9;
    std::uint64_t r10;
    std::uint64_t r11;
    std::uint64_t r12;
    std::uint64_t r13;
    std::uint64_t r14;
    std::uint64_t r15;

    std::uint64_t rip;
    std::uint64_t cs;
    std::uint64_t rflags;
    std::uint64_t rsp;
    std::uint64_t ss;
};
