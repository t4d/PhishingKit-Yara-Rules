rule PK_Zimbra_2025 : Zimbra
{
    meta:
        description = "Phishing Kit impersonating Zimbra login page"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-01-19"
        comment = "Phishing Kit - Zimbra - 'Copyright 2005-2025-All rights reserved'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "assets"
        $spec_file = "submit.php"
        $spec_file2 = "index.html"
        $spec_file3 = "new-back-ground-image.png"
        $spec_file4 = "email-309678_1280-1024x624.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
