rule PK_WalletConnect_only4biz : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1580117526830514176"
        date = "2022-10-12"
        comment = "Phishing Kit - WalletConnect - 'www.only4biz.org'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "connect"
        // specific file found in PhishingKit
        $spec_file = "index-2.html"
        $spec_file2 = "finish.php"
        $spec_file3 = "aave.jpg"
        $spec_file4 = "indexff05ff05ff05ff05.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
