rule PK_Metamask_antibomber : Metamask
{
    meta:
        description = "Phishing Kit impersonating Metamask"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-16"
        comment = "Phishing Kit - Metamask - 'Author Name : ANTI-BOMBER'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "add"
        $spec_dir2 = "func"
        $spec_file1 = "init.php"
        $spec_file2 = "request.php"
        $spec_file3 = "tgm.php"
        $spec_file4 = "to.php"
        $spec_file5 = "metamask-fox.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
