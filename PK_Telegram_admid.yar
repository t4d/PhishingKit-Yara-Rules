rule PK_Telegram_admid : Telegram
{
    meta:
        description = "Phishing Kit impersonating Telegram"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-29"
        comment = "Phishing Kit - Telegram - 'global $ADMID'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "API"
        $spec_dir2 = "img"
        $spec_dir3 = "assets"
        // specific file found in PhishingKit
        $spec_file = "_core.php"
        $spec_file2 = "_rules.json"
        $spec_file3 = "otp.php"
        $spec_file4 = "tgram.svg"
        $spec_file5 = "verified-badge-profile-icon-png.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
