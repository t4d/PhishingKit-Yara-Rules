rule PK_USAA_mozart : USAA
{
    meta:
        description = "Phishing Kit impersonating USAA Savings Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-06"
        comment = "Phishing Kit - USAA - with a 'mozart' directory"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mozart"
        $spec_dir2 = "grabber"
        $spec_dir3 = "logs"
        // specific file found in PhishingKit
        $spec_file = "re_onetime.html"
        $spec_file2 = "onetime.php"
        $spec_file3 = "session_relogin.php"
        $spec_file4 = "9C7F15704715916A9.woff2"
        $spec_file5 = "ent-unified-logon-web.ce50f064965f72792379.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
