rule PK_AdobePDF_antenna : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Adobe PDF Online - contain antenna.css file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "core"
        // specific file found in PhishingKit
        $spec_file = "antenna.css"
        $spec_file2 = "screenshot_23.png"
        $spec_file3 = "fx.js"
        $spec_file4 = "post.php"
        $spec_file5 = "22222222222.png"
        $spec_file6 = "gh-adobe-impersonation-scam-loginwindow.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
