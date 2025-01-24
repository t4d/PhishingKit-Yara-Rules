rule PK_PeapackBank_gate : PeapackBank
{
    meta:
        description = "Phishing Kit impersonating Peapack-Gladstone bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-15"
        comment = "Phishing Kit - Peapack-Glastone Bank"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "css"
        $spec_dir2 = "gate"
        $spec_file1 = "login"
        $spec_file2 = "pgate_t.php"
        $spec_file3 = "pload.php"
        $spec_file4 = "stat.js"
        $spec_file5 = "KFOmCnqEu92Fr1Me5Q.ttf"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
