rule PK_Telenet_antenna : Telenet
{
    meta:
        description = "Phishing Kit impersonating Telenet"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Telenet - contain antenna.css file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "core"
        // specific file found in PhishingKit
        $spec_file = "antenna.css"
        $spec_file2 = "post.php"
        $spec_file3 = "screenshot_4.png"
        $spec_file4 = "screenshot_5.png"
        $spec_file5 = "fx.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
