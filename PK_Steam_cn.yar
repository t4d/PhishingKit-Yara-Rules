rule PK_Steam_cn : Steam
{
    meta:
        description = "Phishing Kit impersonating Steam"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-08"
        comment = "Phishing Kit - Steam - targeting CN users"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "midway"
        $spec_dir2 = "app"
        $spec_file1 = "config.js"
        $spec_file2 = "csgo-dota.png"
        $spec_file3 = "ohsnap.css"
        $spec_file4 = "ohsnap.js"
        $spec_file5 = "steam-icon.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
