rule PK_EZpass_sute : EZpass
{
    meta:
        description = "Phishing Kit impersonating E-ZPass Interagency Group"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-21"
        comment = "Phishing Kit - E-Zpass - using a 'sute_filez' directory name"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "sute_filez"
        $spec_dir1 = "images"
        // specific file found in PhishingKit
        $spec_file = "anu.php"
        $spec_file2 = "thankyou.html"
        $spec_file3 = "process_payment.php"
        $spec_file4 = "E-ZPass_Group_Logo_White.svg"
        $spec_file5 = "sunpass_top_logo_tb.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
