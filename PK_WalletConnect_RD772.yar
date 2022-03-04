rule PK_WalletConnect_RD772 : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-04"
        comment = "Phishing Kit - WalletConnect - using 'wallet-restoration-RD772' directory"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "css"
        // specific file found in PhishingKit
        $spec_file = "restore.html"
        $spec_file2 = "bar.html"
        $spec_file3 = "next.php"
        $spec_file4 = "coin98.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
