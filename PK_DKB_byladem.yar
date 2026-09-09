rule PK_DKB_byladem : DKB
{
    meta:
        description = "Phishing Kit impersonating Das kann Bank (DKB)"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2026-06-17"
        comment = "Phishing Kit - DKB - 'BIC: BYLADEM1001'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "victims"
        $spec_dir2 = "key"
        $spec_file1 = "kartenprufnummer.php"
        $spec_file2 = "verifizieren.php"
        $spec_file3 = "index--1lDWE08.js"
        $spec_file4 = "Comp.php"
        $spec_file5 = "dogango.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
