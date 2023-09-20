rule PK_Ebay_isapi : EBay
{
    meta:
        description = "Phishing Kit impersonating Ebay"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-12"
        comment = "Phishing Kit - EBay - contain 'eBayISAPI.php' file" 

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "eBayISAPI.php"
        $spec_file1 = "act.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
