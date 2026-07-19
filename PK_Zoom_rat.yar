rule PK_Zoom_rat: Zoom
{
    meta:
        description = "Phishing Kit impersonating Zoom for RAT distribution"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-07-17"
        comment = "Phishing Kit - Zoom - distributng Remote Access Tool"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "Windows"
        $spec_dir2 = "Iphone"
        $spec_dir3 = "Android"
        $spec_file = "Google-play.html"
        $spec_file2 = "install-guide.php"
        $spec_file3 = "microsoft-store.php"
        $spec_file4 = "invite.php"
        $spec_file5 = "zoom-icon.webp"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
