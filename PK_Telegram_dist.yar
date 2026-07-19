rule PK_Telegram_dist : Telegram
{
    meta:
        description = "Phishing Kit impersonating Telegram"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-07-05"
        comment = "Phishing Kit - Telegram - contained, mostly, in dist.zip file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "changelogs"
        $spec_dir2 = "tgs"
        $spec_dir3 = "api"
        // specific file found in PhishingKit
        $spec_file = "KFOlCnqEu92Fr1MmEU9fABc4AMP6lbBP.woff2"
        $spec_file2 = "telegram.css"
        $spec_file3 = "modernSave.php"
        $spec_file4 = "voip_recordstart.mp3"
        $spec_file5 = "StarReactionEffect3.json"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
