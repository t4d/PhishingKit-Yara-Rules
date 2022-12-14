rule PK_Zimbra_unknown : Zimbra
{
    meta:
        description = "Phishing Kit impersonating Zimbra login page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-01"
        comment = "Phishing Kit - Zimbra - by '- unknown -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "images"
        $spec_file = "surf3.php"
        $spec_file2 = "need2.php"
        $spec_file3 = "hostname.php"
        $spec_file4 = "zg.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
