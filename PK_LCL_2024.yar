rule PK_LCL_2024 : LCL
{
    meta:
        description = "Phishing Kit impersonating LCL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-14"
        comment = "Phishing Kit - LCL - 2024"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "web"
        $spec_dir2 = "Show_system"
        // specific file found in PhishingKit
        $spec_file = "Select_smsbenef.php"
        $spec_file2 = "code.php"
        $spec_file3 = "proverif.php"
        $spec_file4 = "Select_bannir.php"
        $spec_file5 = "question2.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
