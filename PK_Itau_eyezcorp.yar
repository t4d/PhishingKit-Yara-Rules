rule PK_Itau_eyezcorp : Itau
{
    meta:
        description = "Phishing Kit impersonating Itaù bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-10-04"
        comment = "Phishing Kit - Itau - 'Soporte https://t.me/eyezcorp'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "itau"
        $spec_dir2 = "sistema"
        $spec_file1 = "human_gate.php"
        $spec_file2 = "manda.php"
        $spec_file3 = "cloack_start.php"
        $spec_file4 = "beneficios.12c433be.jpg"
        $spec_file5 = "ver7f9.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
