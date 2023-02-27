rule PK_Aramex_stayle : Aramex
{
    meta:
        description = "Phishing Kit impersonating Aramex"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-27"
        comment = "Phishing Kit - Aramex"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "postoffice"
        $spec_dir2 = "amx"
        $spec_file0 = "lod.php"
        $spec_file1 = "drs2.php"
        $spec_file2 = "confirm.php"
        $spec_file3 = "aramex-logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
