rule PK_NBTbank_packaging : NBTbank
{
    meta:
        description = "Phishing Kit impersonating NBTbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-22"
        comment = "Phishing Kit - NBTbank - 'From: Packaging'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "img"
        // specific file found in PhishingKit
        $spec_file = "db_connect5.php"
        $spec_file2 = "index2.html"
        $spec_file3 = "security.html"
        $spec_file4 = "BANGOR.png"
        $spec_file5 = "RadDockableObject.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_dir*) and
        all of ($spec_file*)
}
