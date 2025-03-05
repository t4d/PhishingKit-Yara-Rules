rule PK_TrustWallet_next : TrustWallet
{
    meta:
        description = "Phishing Kit impersonating Trust Wallet"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-02"
        comment = "Phishing Kit - Trust Wallet - usng next.js"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "chunks"
        $spec_dir2 = "js"
        // specific file found in PhishingKit
        $spec_file = "settings.js"
        $spec_file2 = "1dd3208c-1c33f287c1bdb03a.js"
        $spec_file3 = "raw.9a6dd06f.svg"
        $spec_file4 = "76c08d7e227412bb.css"
        $spec_file5 = "raw.4edbb099.svg"


    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
