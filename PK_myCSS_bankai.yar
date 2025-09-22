rule PK_myCSS_bankai : myCSS
{
    meta:
        description = "Phishing Kit impersonating myCSS, a CSS.ch portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-18"
        comment = "Phishing kit - myCSS - use of 'bankai' named variables"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mycss-login"
        $spec_dir1 = "mycss-ch-ruckerstattungcodeanyappcom"
        // specific file found in PhishingKit
        $spec_file = "load-sms.php"
        $spec_file2 = "3dsec_2293842.html"
        $spec_file3 = "unknown_1835038.gif"
        $spec_file4 = "loadsms_3080281.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
