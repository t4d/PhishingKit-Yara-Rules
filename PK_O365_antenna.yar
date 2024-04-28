rule PK_O365_antenna : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Office 365 - contain antenna.css file"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "core"
        $spec_dir2 = "pw_page"
        $spec_dir3 = "usern_page"
        // specific file found in PhishingKit
        $spec_file = "antenna.css"
        $spec_file2 = "fx.js"
        $spec_file3 = "post.php"
        $spec_file4 = "screenshot_18.png"
        $spec_file5 = "screenshot_19.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
