rule PK_WalletConnect_mysms : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-04"
        comment = "Phishing Kit - WalletConnect - using 'api.mysmssender.com' service for exfiltration"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "wallets"
        $spec_dir2 = "exchange"
        // specific file found in PhishingKit
        $spec_file = "icn-token-pocket.jpg"
        $spec_file2 = "wallet-connect.html"
        $spec_file3 = "index-2.html"
        $spec_file4 = "wallets.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
