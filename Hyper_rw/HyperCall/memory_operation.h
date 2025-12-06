#pragma once
#include <cstdint>

enum class memory_operation_t : std::uint64_t
{
    read_operation,
    write_operation
};
