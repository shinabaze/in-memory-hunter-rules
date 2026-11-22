rule Detect_WinINet_Implant_With_Pipe_Redirection
{
    meta:
        description = "Detects implants leveraging WinINet HTTP/S APIs coupled with anonymous pipe execution"
        author = "Shinabaze Ajiya"
        reference = "T1071.001 / T1059.003"
        severity = "HIGH"

    strings:
        // WinINet APIs
        $net1 = "InternetOpenA" ascii wide nocase
        $net2 = "HttpOpenRequestA" ascii wide nocase
        $net3 = "HttpSendRequestA" ascii wide nocase
        $net4 = "InternetReadFile" ascii wide nocase

        // Anonymous pipe and process creation APIs
        $pipe1 = "CreatePipe" ascii wide nocase
        $pipe2 = "SetHandleInformation" ascii wide nocase
        $pipe3 = "PeekNamedPipe" ascii wide nocase
        $proc1 = "CreateProcessA" ascii wide nocase
        $proc2 = "CreateProcessW" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($net*)) and
        (1 of ($pipe*)) and
        (1 of ($proc*))
}
