rule PK_Aramex_don : Aramex
{
    meta:
        description = "Phishing Kit impersonating Aramex"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-04"
        comment = "Phishing Kit - Aramex - 'From: ARMEX <don@cool.com>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "be"
        $spec_file0 = "index3.php"
        $spec_file1 = "snd3.php"
        $spec_file2 = "master.jpg"
        $spec_file3 = "visa.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
