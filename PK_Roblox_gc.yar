rule PK_Roblox_gc : Roblox
{
    meta:
        description = "Phishing Kit impersonating Roblox"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-08-26"
        comment = "Phishing Kit - Roblox - fake gift card"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_file = "script.js"
        $spec_file2 = "avatar.png"
        $spec_file3 = "robux_new.jfif"
        $spec_file4 = "coin.png"
        
    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
