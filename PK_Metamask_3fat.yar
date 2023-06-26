rule PK_Metamask_3fat : Metamask
{
    meta:
        description = "Phishing Kit impersonating Metamask"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-26"
        comment = "Phishing Kit - Metamask - using 3fat.php file"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "wech"
        $spec_dir2 = "borwsers"
        $spec_file1 = "info.php"
        $spec_file2 = "3fat.php"
        $spec_file3 = "success.html"
        $spec_file4 = "logo.53f2bee2f357c4247916f6ee01a2332b.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
