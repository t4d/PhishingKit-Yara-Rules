rule PK_O365_Priv9 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-20"
        comment = "Phishing Kit - O365 - code reuse from PK_O365_Priv8"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file = "pt.htm"
        $spec_file2 = "ind.php"
        $spec_file3 = "n.php"
        $spec_file4 = "index.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
