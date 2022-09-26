rule PK_WeTransfer_dubby : WeTransfer
{
    meta:
        description = "Phishing Kit impersonating WeTransfer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-23"
        comment = "Phishing Kit - WeTransfer - '-Created BY Dubby-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "img"
        // specific file found in PhishingKit
        $spec_file = "bt.php"
        $spec_file1 = "index_.php"
        $spec_file2 = "2.jpg"
        $spec_file3 = "index.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_dir and 
        all of ($spec_file*)
}
