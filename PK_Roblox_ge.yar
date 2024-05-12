rule PK_Roblox_ge : Roblox
{
    meta:
        description = "Phishing Kit impersonating Roblox"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-10"
        comment = "Phishing Kit - Roblox - georgian messages"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = ".idea"
        $spec_dir2 = "7936348760"
        // specific file found in PhishingKit
        $spec_file = "shevida.js"
        $spec_file2 = "userprofile.html"
        $spec_file3 = "login.html"
        
    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
