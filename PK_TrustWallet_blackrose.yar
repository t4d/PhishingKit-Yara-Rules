rule PK_TrustWallet_blackrose : TrustWallet
{
    meta:
        description = "Phishing Kit impersonating Trust Wallet"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-02-09"
        comment = "Phishing Kit - Trust Wallet - 'Main Author: @BLACKROSE_1337'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Folder"
        $spec_dir2 = "TS"
        $spec_dir3 = "system"
        // specific file found in PhishingKit
        $spec_file = "Info_Processing.php"
        $spec_file2 = "logo(35).png"
        $spec_file3 = "login_wallet24.js"
        $spec_file4 = "Opane.html"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
