rule PK_Truist_RD596 : Truist
{
    meta:
        description = "Phishing Kit impersonating Truist Bank (SunTrust)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-05"
        comment = "Phishing Kit - Truist Bank, Suntrust - RD596"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "includes"
        $spec_file1 = "detail.php"
        $spec_file2 = "em.php"
        $spec_file3 = "thank.php"
        $spec_file4 = "suntrust-now-truist-white-horizontal.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
