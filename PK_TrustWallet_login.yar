rule PK_TrustWallet_login : TrustWallet
{
    meta:
        description = "Phishing Kit impersonating Trust Wallet"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-27"
        comment = "Phishing Kit - Trust Wallet - 'New Login wallet'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "favicons"
        $spec_dir2 = "js"
        // specific file found in PhishingKit
        $spec_file = "IBMPlexSans-IBMPlexSans-Bold.woff"
        $spec_file2 = "js-platform.js"
        $spec_file3 = "send.php"
        $spec_file4 = "images-trust_logotype.svg"
        $spec_file5 = "home_trustwallet_app.png"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
