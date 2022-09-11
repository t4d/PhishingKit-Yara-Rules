rule PK_UPS_aron : UPS
{
    meta:
        description = "Phishing Kit impersonating UPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-30"
        comment = "Phishing Kit - UPS - '=[ UPS ARON-TN ]='"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "VBV_files"
        // specific file found in PhishingKit
        $spec_file = "settings.php"
        $spec_file2 = "xx.png"
        $spec_file3 = "thankyou.php"
        $spec_file4 = "Charles.php"
        $spec_file5 = "behi.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
