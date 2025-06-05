rule PK_IDME_tr32cs : IDME
{
    meta:
        description = "Phishing Kit impersonating ID.me"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-05"
        comment = "Phishing Kit - IDME - tr32cs.zip"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "bootstrap"
        // specific files found in PhishingKit
        $spec_file1 = "otp1.html"
        $spec_file2 = "caf.html"
        $spec_file3 = "ptin.html"
        $spec_file4 = "IDme@4x.png"
        $spec_file5 = "telegram.php"
        $spec_file6 = "sm.jpg"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
