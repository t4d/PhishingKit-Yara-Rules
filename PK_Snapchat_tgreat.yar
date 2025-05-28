rule PK_Snapchat_tgreat : Snapchat
{
    meta:
        description = "Phishing Kit impersonating Snapchat"
        licence = "1GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-26"
        comment = "Phishing Kit - Snapchat - 'Telegram ID: @tgreat_coder Snap Chat'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "myeyes.php"
        $spec_file2 = "reg5.php"
        $spec_file3 = "number.html"
        $spec_file4 = "snapchat-app-icon.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
