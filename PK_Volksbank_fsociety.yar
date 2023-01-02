rule PK_Volksbank_fsociety : Volksbank
{
    meta:
        description = "Phishing Kit impersonating Volksbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-02"
        comment = "Phishing Kit - Volksbank - 'C0d3d by fS0C13TY_Team'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "VR"
        $spec_dir2 = "Select"
        $spec_file1 = "Entry_Error.html"
        $spec_file2 = "admin.php"
        $spec_file3 = "sand_email.php"
        $spec_file4 = "dz-privatbank.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
