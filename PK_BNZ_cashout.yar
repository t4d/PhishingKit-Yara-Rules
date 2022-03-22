rule PK_BNZ_cashout : BNZ
{
    meta:
        description = "Phishing Kit impersonating Box"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-14"
        comment = "Phishing Kit - BNZ - 'BY xxx-cashout'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "BNZ Login_files"
        $spec_dir2 = "uploads"
        $spec_file1 = "id.php"
        $spec_file2 = "upload.php"
        $spec_file3 = "ejktHEz.png"
        $spec_file4 = "f.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
