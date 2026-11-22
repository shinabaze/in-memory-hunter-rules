rule Detect_Reflective_Loader_PEB_Walk
{
    meta:
        description = "Detects in-memory shellcode walking PEB to dynamically locate ntdll/kernel32"
        author = "Shinabaze Ajiya"
        reference = "T1620 - Reflective Code Loading"
        severity = "HIGH"

    strings:
        // x64: mov rax, gs:[0x60] (PEB)
        $peb64_1 = { 65 48 8B 04 25 60 00 00 00 }
        $peb64_2 = { 65 48 8B 05 60 00 00 00 }
        $peb64_3 = { 65 48 8B 14 25 60 00 00 00 }

        // x86: mov eax, fs:[0x30] (PEB)
        $peb32_1 = { 64 A1 30 00 00 00 }
        $peb32_2 = { 64 8B 05 30 00 00 00 }
        $peb32_3 = { 64 8B 1D 30 00 00 00 }

        // PEB -> Ldr (0x18 on x64 or 0x0c on x86) -> InMemoryOrderModuleList
        $ldr_walk64 = { 48 8B ?? 18 48 8B ?? 20 }
        $ldr_walk32 = { 8B ?? 0C 8B ?? 14 }

        // ROR-13 API Hashing Loop: ror eax, 0x0d; add edx, eax
        $ror13_x86_1 = { C1 C8 0D 03 D0 }
        $ror13_x86_2 = { C1 C9 0D 03 D1 }
        $ror13_x64_1 = { C1 CF 0D 03 ?? }

    condition:
        (1 of ($peb64*) and ($ldr_walk64 or 1 of ($ror13*))) or
        (1 of ($peb32*) and ($ldr_walk32 or 1 of ($ror13*)))
}
