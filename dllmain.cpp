#include <windows.h>
#include <MinHook.h>

#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <span>

namespace {

    constexpr std::ptrdiff_t kResponseSuccess = 0x238;
    constexpr std::ptrdiff_t kResponseMessage = 0x240;
    constexpr std::ptrdiff_t kResponseIsPaid = 0x260;
    constexpr std::ptrdiff_t kOwnerId = 0x20;
    constexpr std::ptrdiff_t kUserName = 0xA8;
    constexpr std::ptrdiff_t kUserIp = 0xC8;
    constexpr std::ptrdiff_t kUserHwid = 0xE8;
    constexpr std::ptrdiff_t kUserCreateDate = 0x108;
    constexpr std::ptrdiff_t kUserLastLogin = 0x128;
    constexpr std::ptrdiff_t kUserSubscriptions = 0x148;

    using LoadResponseDataFn = void(__fastcall*)(void* self, void* json);
    using LicenseFn = void(__fastcall*)(void* self, void* key, void* code);
    using CheckFn = void(__fastcall*)(void* self, bool check_paid);
    using LocalAuthValidFn = bool(__fastcall*)(void* self, bool require_paid);
    using CheckSectionIntegrityFn = bool(__fastcall*)(const char* section_name, bool fix);
    using OperatorNewFn = void* (__fastcall*)(std::size_t size);

    LoadResponseDataFn g_load_response_data = nullptr;
    LicenseFn g_license = nullptr;
    CheckFn g_check = nullptr;
    LocalAuthValidFn g_local_auth_valid = nullptr;
    CheckSectionIntegrityFn g_check_section_integrity = nullptr;
    OperatorNewFn g_operator_new = nullptr;
    HANDLE g_console = INVALID_HANDLE_VALUE;

    struct Signature {
        const char* name;
        std::span<const std::uint8_t> bytes;
        const char* mask;
    };

    template <std::size_t N>
    constexpr Signature make_signature(
        const char* name,
        const std::array<std::uint8_t, N>& bytes,
        const char(&mask)[N + 1]) {
        return { name, bytes, mask };
    }

    constexpr std::array<std::uint8_t, 33> kLoadResponseBytes{
        std::uint8_t{0x48}, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
        0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x8D, 0x6C, 0x24, 0xD9, 0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00
    };
    constexpr auto kLoadResponse = make_signature(
        "load_response_data", kLoadResponseBytes, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    constexpr std::array<std::uint8_t, 24> kLicenseBytes{
        std::uint8_t{0x48}, 0x89, 0x5C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54,
        0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0xFC,
        0xFF, 0xFF
    };
    constexpr auto kLicense = make_signature(
        "KeyAuth::api::license", kLicenseBytes, "xxxxxxxxxxxxxxxxxxxxxxxx");

    constexpr std::array<std::uint8_t, 38> kCheckBytes{
        std::uint8_t{0x48}, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70,
        0x18, 0x48, 0x89, 0x78, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
        0x41, 0x57, 0x48, 0x8D, 0xA8, 0xB8, 0xFE, 0xFF, 0xFF, 0x48, 0x81, 0xEC,
        0x20, 0x02, 0x00, 0x00
    };
    constexpr auto kCheck = make_signature(
        "KeyAuth::api::check", kCheckBytes, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    constexpr std::array<std::uint8_t, 32> kLocalAuthBytes{
        std::uint8_t{0x48}, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
        0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x0F, 0xB6, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0xF2, 0x48, 0x8B, 0xD9
    };
    constexpr auto kLocalAuth = make_signature(
        "local_auth_valid", kLocalAuthBytes, "xxxxxxxxxxxxxxxxxxxxx????xxxxxxx");

    constexpr std::array<std::uint8_t, 25> kIntegrityBytes{
        std::uint8_t{0x48}, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18,
        0x56, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x80,
        0x02, 0x00, 0x00
    };
    constexpr auto kIntegrity = make_signature(
        "check_section_integrity", kIntegrityBytes, "xxxxxxxxxxxxxxxxxxxxxxxxx");

    constexpr std::array<std::uint8_t, 23> kOperatorNewBytes{
        std::uint8_t{0x40}, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0xEB,
        0x0F, 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74,
        0x13
    };
    constexpr auto kOperatorNew = make_signature(
        "operator new", kOperatorNewBytes, "xxxxxxxxxxxxxxx????xxxx");

    void log(const char* format, ...) { // acmak istiyorsaniz size bagli
        //char message[2048]{};
        //va_list arguments;
        //va_start(arguments, format);
        //std::vsnprintf(message, sizeof(message), format, arguments);
        //va_end(arguments);

        //SYSTEMTIME time{};
        //GetLocalTime(&time);

        //char line[2304]{};
        //std::snprintf(
        //    line,
        //    sizeof(line),
        //    "[%02u:%02u:%02u.%03u] [T%lu] %s\r\n",
        //    time.wHour,
        //    time.wMinute,
        //    time.wSecond,
        //    time.wMilliseconds,
        //    static_cast<unsigned long>(GetCurrentThreadId()),
        //    message);

        //if (g_console != INVALID_HANDLE_VALUE) {
        //    DWORD written = 0;
        //    WriteFile(
        //        g_console,
        //        line,
        //        static_cast<DWORD>(std::strlen(line)),
        //        &written,
        //        nullptr);
        //}
        //OutputDebugStringA(line);
    }

    void open_console() {
        //if (GetConsoleWindow() == nullptr) {
        //    AllocConsole();
        //}
        //SetConsoleTitleW(L"KeyAuth response hook log");

        //g_console = CreateFileW(
        //    L"CONOUT$",
        //    GENERIC_WRITE | GENERIC_READ,
        //    FILE_SHARE_WRITE | FILE_SHARE_READ,
        //    nullptr,
        //    OPEN_EXISTING,
        //    0,
        //    nullptr);

        //log("console initialized; module=%p process=%lu",
        //    GetModuleHandleW(nullptr),
        //    static_cast<unsigned long>(GetCurrentProcessId()));
    }

    void force_response(void* self) {
        if (self == nullptr) {
            log("force_response: null api object");
            return;
        }

        auto* object = static_cast<std::byte*>(self);
        const auto previous_success = std::to_integer<unsigned int>(object[kResponseSuccess]);
        const auto previous_paid = std::to_integer<unsigned int>(object[kResponseIsPaid]);
        object[kResponseSuccess] = std::byte{ 1 };
        object[kResponseIsPaid] = std::byte{ 1 };
        log("force_response: api=%p success %u->1 isPaid %u->1",
            self,
            previous_success,
            previous_paid);
    }

    bool readable_range(const void* address, std::size_t size) {
        if (address == nullptr || size == 0) {
            return false;
        }

        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(address, &information, sizeof(information)) == 0 ||
            information.State != MEM_COMMIT ||
            (information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
            return false;
        }

        const auto begin = reinterpret_cast<std::uintptr_t>(address);
        const auto region_end =
            reinterpret_cast<std::uintptr_t>(information.BaseAddress) + information.RegionSize;
        return begin <= region_end && size <= region_end - begin;
    }

    bool writable_range(const void* address, std::size_t size) {
        if (!readable_range(address, size)) {
            return false;
        }

        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(address, &information, sizeof(information)) == 0) {
            return false;
        }

        const DWORD protection = information.Protect & 0xFF;
        return protection == PAGE_READWRITE ||
            protection == PAGE_WRITECOPY ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
    }

    bool write_msvc_string(void* object, const char* replacement, const char* field_name) {
        if (object == nullptr || replacement == nullptr || !writable_range(object, 0x20)) {
            log("write string: %s object=%p is not writable", field_name, object);
            return false;
        }

        auto* value = static_cast<std::byte*>(object);
        const std::size_t replacement_size = std::strlen(replacement);
        auto* size = reinterpret_cast<std::size_t*>(value + 0x10);
        auto* capacity = reinterpret_cast<std::size_t*>(value + 0x18);

        char* destination = nullptr;
        if (*capacity <= 15) {
            if (replacement_size <= 15) {
                destination = reinterpret_cast<char*>(value);
                *capacity = 15;
            }
            else {
                if (g_operator_new == nullptr) {
                    log("write string: %s needs target allocation, but operator new is unavailable",
                        field_name);
                    return false;
                }
                destination = static_cast<char*>(g_operator_new(replacement_size + 1));
                if (destination == nullptr ||
                    !writable_range(destination, replacement_size + 1)) {
                    log("write string: %s target allocation failed", field_name);
                    return false;
                }
                *reinterpret_cast<char**>(value) = destination;
                *capacity = replacement_size;
                log("write string: %s allocated target-owned buffer=%p size=%zu",
                    field_name,
                    destination,
                    replacement_size + 1);
            }
        }
        else {
            destination = *reinterpret_cast<char**>(value);
            if (replacement_size > *capacity) {
                if (g_operator_new == nullptr) {
                    log("write string: %s cannot grow without target operator new", field_name);
                    return false;
                }
                destination = static_cast<char*>(g_operator_new(replacement_size + 1));
                if (destination == nullptr ||
                    !writable_range(destination, replacement_size + 1)) {
                    log("write string: %s target growth allocation failed", field_name);
                    return false;
                }
                *reinterpret_cast<char**>(value) = destination;
                *capacity = replacement_size;
            }
            else if (!writable_range(destination, replacement_size + 1)) {
                log("write string: %s heap buffer=%p size=%zu capacity=%zu rejected",
                    field_name,
                    destination,
                    replacement_size,
                    *capacity);
                return false;
            }
        }

        std::memcpy(destination, replacement, replacement_size + 1);
        *size = replacement_size;
        log("write string: %s=\"%s\" object=%p buffer=%p capacity=%zu",
            field_name,
            replacement,
            object,
            destination,
            *capacity);
        return true;
    }

    bool initialize_msvc_sso_string(void* object, const char* text) {
        const std::size_t size = std::strlen(text);
        if (object == nullptr || size > 15 || !writable_range(object, 0x20)) {
            return false;
        }

        std::memset(object, 0, 0x20);
        std::memcpy(object, text, size + 1);
        auto* bytes = static_cast<std::byte*>(object);
        *reinterpret_cast<std::size_t*>(bytes + 0x10) = size;
        *reinterpret_cast<std::size_t*>(bytes + 0x18) = 15;
        return true;
    }

    void force_subscription(void* self, const char* expiry) {
        struct RawVector {
            std::byte* first;
            std::byte* last;
            std::byte* end;
        };

        auto* vector = reinterpret_cast<RawVector*>(
            static_cast<std::byte*>(self) + kUserSubscriptions);
        if (!writable_range(vector, sizeof(*vector))) {
            log("force_subscription: vector object=%p is not writable", vector);
            return;
        }

        constexpr std::size_t kSubscriptionSize = 0x40;
        std::byte* subscription = nullptr;

        if (vector->first == nullptr && vector->last == nullptr && vector->end == nullptr) {
            if (g_operator_new == nullptr) {
                log("force_subscription: target operator new is unavailable");
                return;
            }
            subscription = static_cast<std::byte*>(g_operator_new(kSubscriptionSize));
            if (subscription == nullptr || !writable_range(subscription, kSubscriptionSize)) {
                log("force_subscription: target allocation failed");
                return;
            }
            vector->first = subscription;
            vector->last = subscription + kSubscriptionSize;
            vector->end = vector->last;
            log("force_subscription: allocated target-owned vector storage=%p", subscription);
        }
        else if (vector->first != nullptr &&
            vector->end >= vector->first + kSubscriptionSize &&
            writable_range(vector->first, kSubscriptionSize)) {
            subscription = vector->first;
            vector->last = vector->first + kSubscriptionSize;
            log("force_subscription: reused vector storage=%p", subscription);
        }
        else {
            log("force_subscription: rejected vector layout first=%p last=%p end=%p",
                vector->first,
                vector->last,
                vector->end);
            return;
        }

        if (!initialize_msvc_sso_string(subscription, "default") ||
            !initialize_msvc_sso_string(subscription + 0x20, expiry)) {
            log("force_subscription: string construction failed");
            return;
        }
        log("force_subscription: name=\"default\" expiry=\"%s\" size=1", expiry);
    }

    void force_identity(void* self) {
        if (self == nullptr) {
            log("force_identity: null api object");
            return;
        }

        auto* object = static_cast<std::byte*>(self);
        write_msvc_string(object + kUserName, "diwnxss", "user_data.username");
        write_msvc_string(object + kUserIp, "95.5.105.199", "user_data.ip");
        write_msvc_string(
            object + kUserHwid,
            "S-1-5-21-2905609133-2690752310-3489066890-1001",
            "user_data.hwid");
        write_msvc_string(object + kUserCreateDate, "1741792316", "user_data.createdate");
        write_msvc_string(object + kUserLastLogin, "1741923234", "user_data.lastlogin");
        force_subscription(self, "1773349242");
        write_msvc_string(object + kResponseMessage, "Authenticated", "response.message");
    }

    void pin_owner_atom(void* self) {
        if (self == nullptr) {
            log("pin_owner_atom: null api object");
            return;
        }

        const auto* value = static_cast<const std::byte*>(self) + kOwnerId;
        if (!readable_range(value, 0x20)) {
            log("pin_owner_atom: ownerid object at %p is unreadable", value);
            return;
        }

        const auto size = *reinterpret_cast<const std::size_t*>(value + 0x10);
        const auto capacity = *reinterpret_cast<const std::size_t*>(value + 0x18);
        if (size == 0 || size > 255 || capacity < size) {
            log("pin_owner_atom: rejected ownerid layout size=%zu capacity=%zu",
                size,
                capacity);
            return;
        }

        const char* text = nullptr;
        if (capacity <= 15) {
            text = reinterpret_cast<const char*>(value);
        }
        else {
            text = *reinterpret_cast<const char* const*>(value);
        }

        if (!readable_range(text, size + 1) || text[size] != '\0') {
            log("pin_owner_atom: ownerid buffer %p is invalid (size=%zu)", text, size);
            return;
        }
        const ATOM atom = GlobalAddAtomA(text);
        log("pin_owner_atom: ownerid=\"%.*s\" atom=0x%04X",
            static_cast<int>(size),
            text,
            static_cast<unsigned int>(atom));
    }

    struct ImageView {
        std::uint8_t* base{};
        IMAGE_NT_HEADERS64* nt{};
    };

    ImageView main_image() {
        auto* base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
        if (base == nullptr) {
            return {};
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return {};
        }

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return {};
        }
        return { base, nt };
    }

    bool matches(const std::uint8_t* candidate, const Signature& signature) {
        for (std::size_t index = 0; index < signature.bytes.size(); ++index) {
            if (signature.mask[index] == 'x' && candidate[index] != signature.bytes[index]) {
                return false;
            }
        }
        return true;
    }

    void* find_unique(const ImageView& image, const Signature& signature) {
        log("signature scan: %s (%zu bytes)", signature.name, signature.bytes.size());
        void* match = nullptr;
        std::size_t count = 0;

        auto* section = IMAGE_FIRST_SECTION(image.nt);
        for (WORD index = 0; index < image.nt->FileHeader.NumberOfSections; ++index, ++section) {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
                continue;
            }

            auto* start = image.base + section->VirtualAddress;
            const auto size = static_cast<std::size_t>(section->Misc.VirtualSize);
            if (size < signature.bytes.size()) {
                continue;
            }

            for (std::size_t offset = 0; offset <= size - signature.bytes.size(); ++offset) {
                if (matches(start + offset, signature)) {
                    match = start + offset;
                    ++count;
                    log("signature candidate: %s at %p", signature.name, match);
                }
            }
        }

        if (count != 1) {
            log("signature failure: %s match count=%zu", signature.name, count);
            return nullptr;
        }
        log("signature resolved: %s -> %p", signature.name, match);
        return match;
    }

    void __fastcall hook_load_response_data(void* self, void* json) {
        log("load_response_data: enter api=%p json=%p", self, json);
        g_load_response_data(self, json);
        log("load_response_data: original returned");
        force_response(self);
        log("load_response_data: leave");
    }

    void __fastcall hook_license(void* self, void* key, void* code) {
        log("license: enter api=%p key_object=%p code_object=%p", self, key, code);
        g_license(self, key, code);
        log("license: original returned");
        force_response(self);
        force_identity(self);
        pin_owner_atom(self);
        log("license: leave");
    }

    void __fastcall hook_check(void* self, bool check_paid) {
        log("check: enter api=%p require_paid=%s",
            self,
            check_paid ? "true" : "false");
        g_check(self, check_paid);
        log("check: original returned");
        force_response(self);
        pin_owner_atom(self);
        log("check: leave");
    }

    bool __fastcall hook_local_auth_valid(void* self, bool require_paid) {
        log("local_auth_valid: api=%p require_paid=%s -> true",
            self,
            require_paid ? "true" : "false");
        return true;
    }

    bool __fastcall hook_check_section_integrity(const char* section_name, bool fix) {
        log("check_section_integrity: section=\"%s\" fix=%s -> false",
            section_name != nullptr ? section_name : "<null>",
            fix ? "true" : "false");
        return false;
    }

    template <typename T>
    bool create_hook(void* target, void* detour, T* original) {
        const MH_STATUS status =
            MH_CreateHook(target, detour, reinterpret_cast<void**>(original));
        log("MH_CreateHook: target=%p detour=%p status=%s trampoline=%p",
            target,
            detour,
            MH_StatusToString(status),
            status == MH_OK ? reinterpret_cast<void*>(*original) : nullptr);
        return status == MH_OK;
    }

    DWORD WINAPI initialize(void*) {
        open_console();
        log("initialization started");

        const auto image = main_image();
        if (image.base == nullptr) {
            log("main image validation failed");
            return 1;
        }
        log("main image: base=%p image_size=0x%lX sections=%u",
            image.base,
            static_cast<unsigned long>(image.nt->OptionalHeader.SizeOfImage),
            static_cast<unsigned int>(image.nt->FileHeader.NumberOfSections));

        void* load_response = find_unique(image, kLoadResponse);
        void* license = find_unique(image, kLicense);
        void* check = find_unique(image, kCheck);
        void* local_auth = find_unique(image, kLocalAuth);
        void* integrity = find_unique(image, kIntegrity);
        void* operator_new = find_unique(image, kOperatorNew);
        if (load_response == nullptr || license == nullptr || check == nullptr ||
            local_auth == nullptr || integrity == nullptr || operator_new == nullptr) {
            log("initialization aborted: one or more signatures failed");
            return 2;
        }
        g_operator_new = reinterpret_cast<OperatorNewFn>(operator_new);
        log("target allocator: operator new=%p", operator_new);

        const MH_STATUS initialize_status = MH_Initialize();
        log("MH_Initialize: %s", MH_StatusToString(initialize_status));
        if (initialize_status != MH_OK) {
            return 3;
        }

        if (!create_hook(load_response, reinterpret_cast<void*>(&hook_load_response_data),
            &g_load_response_data) ||
            !create_hook(license, reinterpret_cast<void*>(&hook_license), &g_license) ||
            !create_hook(check, reinterpret_cast<void*>(&hook_check), &g_check) ||
            !create_hook(local_auth, reinterpret_cast<void*>(&hook_local_auth_valid),
                &g_local_auth_valid) ||
            !create_hook(integrity, reinterpret_cast<void*>(&hook_check_section_integrity),
                &g_check_section_integrity)) {
            log("hook creation failed; uninitializing");
            MH_Uninitialize();
            return 4;
        }

        const MH_STATUS queue_load = MH_QueueEnableHook(load_response);
        const MH_STATUS queue_license = MH_QueueEnableHook(license);
        const MH_STATUS queue_check = MH_QueueEnableHook(check);
        const MH_STATUS queue_local = MH_QueueEnableHook(local_auth);
        const MH_STATUS queue_integrity = MH_QueueEnableHook(integrity);
        log("queue hooks: response=%s license=%s check=%s local=%s integrity=%s",
            MH_StatusToString(queue_load),
            MH_StatusToString(queue_license),
            MH_StatusToString(queue_check),
            MH_StatusToString(queue_local),
            MH_StatusToString(queue_integrity));

        const MH_STATUS apply_status = MH_ApplyQueued();
        log("MH_ApplyQueued: %s", MH_StatusToString(apply_status));
        if (queue_load != MH_OK ||
            queue_license != MH_OK ||
            queue_check != MH_OK ||
            queue_local != MH_OK ||
            queue_integrity != MH_OK ||
            apply_status != MH_OK) {
            log("enabling hooks failed; uninitializing");
            MH_Uninitialize();
            return 5;
        }

        log("all hooks installed successfully");
        return 0;
    }

} // namespace

void vmpudxxlxlxlxlxlxl() // most likely will work its one of my old codes so...
{
    unsigned long old_protect = 0;
    const auto ntdll = GetModuleHandleA(("ntdll.dll"));
    if (!ntdll)
        return;

    unsigned char callcode = ((unsigned char*)GetProcAddress(ntdll, ("NtQuerySection")))[4] - 1;
    unsigned char restore[] = { 0x4C, 0x8B, 0xD1, 0xB8, callcode };

    const auto nt_protect_virtual_mem = (unsigned char*)GetProcAddress(ntdll, ("NtProtectVirtualMemory"));
    if (!nt_protect_virtual_mem)
        return;

    VirtualProtect(nt_protect_virtual_mem, sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(nt_protect_virtual_mem, restore, sizeof(restore));
    VirtualProtect(nt_protect_virtual_mem, sizeof(restore), old_protect, &old_protect);
    //std::cout << "vmp patched";
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        vmpudxxlxlxlxlxlxl();
        const HANDLE thread = CreateThread(nullptr, 0, initialize, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}
