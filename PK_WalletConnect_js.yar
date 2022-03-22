rule PK_WalletConnect_js : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-16"
        comment = "Phishing Kit - WalletConnect - using a JS file with email credentials inside"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "connect"
        // specific file found in PhishingKit
        $spec_file = "index-2.html"
        $spec_file2 = "app.js"
        $spec_file3 = "Blockchain.png"
        $spec_file4 = "indexff05ff05.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
