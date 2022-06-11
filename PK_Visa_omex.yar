rule PK_Visa_omex : Visa
{
    meta:
        description = "Phishing Kit impersonating Visa"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1535144320906543104"
        date = "2022-06-10"
        comment = "Phishing Kit - Visa - '=xX OMEX Xx='"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "data"
        $spec_dir2 = "gogo"
        $spec_file1 = "gogo.php"
        $spec_file2 = "E.php"
        $spec_file3 = "log2.php"
        $spec_file4 = "2x2.htm"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
