rule PK_EIM_antenna : Etisalat
{
    meta:
        description = "Phishing Kit impersonating Etisalat Internet Mail (EIM)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Etisalat - contain antenna.css file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "core"
        // specific file found in PhishingKit
        $spec_file = "antenna.css"
        $spec_file2 = "fx.js"
        $spec_file3 = "post.php"
        $spec_file4 = "screenshot_2.png"
        $spec_file5 = "screenshot_3.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
