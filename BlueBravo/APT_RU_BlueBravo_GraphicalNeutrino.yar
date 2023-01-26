rule APT_RU_BlueBravo_GraphicalNeutrino {

    meta:
        author = "Insikt Group, Recorded Future"
        date = "2023-01-13"
        description = "Detects the hashing algorithm and string decryption routine used by GraphicalNeutrino"
        version = "1.0"
        hash = "381a3c6c7e119f58dfde6f03a9890353a20badfa1bfa7c38ede62c6b0692103c"
        hash = "1cffaf3be725d1514c87c328ca578d5df1a86ea3b488e9586f9db89d992da5c4"

    strings:
        /*
        6b701cc7 31 d2           XOR        EDX,EDX
        6b701cc9 49 01 c0        ADD        R8,RAX
        6b701ccc 4c 39 c0        CMP        RAX,R8
        6b701ccf 74 0a           JZ         LAB_6b701cdb
        6b701cd1 0f be 08        MOVSX      ECX,byte ptr [RAX]
        6b701cd4 48 ff c0        INC        RAX
        6b701cd7 01 ca           ADD        EDX,ECX
        6b701cd9 eb f1           JMP        LAB_6b701ccc
        */
        $c1 = { 31 d2 4? 01 c0 4? 39 c0 74 ?? 0f be 08 4? ff c0 01 ca eb  } // hash user_computername 
        /*
        6b71e185 48 39 d0        CMP        RAX,param_2
        6b71e188 74 19           JZ         LAB_6b71e1a3
        6b71e18a 48 89 c1        MOV        param_1,RAX
        6b71e18d 4d 89 c2        MOV        R10,param_3
        6b71e190 83 e1 07        AND        param_1,0x7
        6b71e193 48 c1 e1 03     SHL        param_1,0x3
        6b71e197 49 d3 ea        SHR        R10,param_1
        6b71e19a 45 30 14 01     XOR        byte ptr [R9 + RAX*0x1],R10B
        6b71e19e 48 ff c0        INC        RAX
        6b71e1a1 eb e2           JMP        LAB_6b71e185
        */
        $c2 = { 4? 39 d0 74 ?? 4? 89 c1 4? 89 c2 83 e1 ?? 4? c1 e1 ?? 4? d3 ea 4? 30 14 01 4? ff c0 eb } // string decrypt
    condition:
        uint16(0) == 0x5a4d 
        and all of them
}
