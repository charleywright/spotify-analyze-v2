#pragma once

#include <cinttypes>
//#include "MinHook.h"
#include "subhook.h"

namespace hooking
{
    bool hook();
    void unhook();

    namespace detail
    {
        struct hooks
        {
            static void shn_encrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes);
            static void shn_decrypt(struct shn_ctx *c, std::uint8_t *buf, int num_bytes);
        };

        bool get_executable_memory(std::uint64_t *len);
        inline std::uint8_t *executable_memory_location = nullptr;

        inline subhook_t shn_encrypt_hook;
        inline subhook_t shn_decrypt_hook;
    }
}
