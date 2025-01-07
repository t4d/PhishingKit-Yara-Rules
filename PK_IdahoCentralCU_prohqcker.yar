rule PK_IdahoCentralCU_prohqcker : Idaho Central Credit Union
{
    meta:
        description = "Phishing Kit impersonating Idaho Central Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-07"
        comment = "Phishing Kit - Idaho Central Credit Union - contains 'prohqcker' files"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir1 = "file"
        $spec_dir2 = "ICCU"
        // specific files found in PhishingKit
        $spec_file1 = "email.html"
        $spec_file2 = "prohqcker6.php"
        $spec_file3 = "personal.html"
        $spec_file4 = "isotope.min.css"
        $spec_file5 = "Alkami.woff2"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
