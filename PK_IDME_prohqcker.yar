rule PK_IDME_prohqcker : IDME
{
    meta:
        description = "Phishing Kit impersonating ID.me"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-07"
        comment = "Phishing Kit - IDME - 'Prohqcker_Bot*IDME'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific files found in PhishingKit
        $spec_file1 = "prohqcker3.php"
        $spec_file2 = "personal.html"
        $spec_file3 = "IRS-Logo.svg"
        $spec_file4 = "ID.me_6.28.21.png"
        $spec_file5 = "id.ico"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
