rule PK_BankID_poko : BankID
{
    meta:
        description = "Phishing Kit impersonating BankID"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-12-17"
        comment = "Phishing Kit - BankID - 'poko90000001'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "folder"
        $spec_dir2 = "file"
        $spec_dir3 = "logos"
        // specific file found in PhishingKit
        $spec_file = "r5.php"
        $spec_file2 = "wait4.html"
        $spec_file3 = "shoflhih.css"
        $spec_file4 = "3625_banklogo.jpeg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
