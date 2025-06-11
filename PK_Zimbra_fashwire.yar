rule PK_Zimbra_fashwire : Zimbra
{
    meta:
        description = "Phishing Kit impersonating Zimbra login page"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-08"
        comment = "Phishing Kit - Zimbra - 'Created By FASHWIRE'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "imbra"
        $spec_file = "fashinc.php"
        $spec_file2 = "tresor.php"
        $spec_file3 = "tresor1.php"
        $spec_file4 = "tresorzimbra"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
