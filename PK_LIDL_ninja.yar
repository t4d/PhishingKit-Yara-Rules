rule PK_LIDL_ninja : LIDL
{
    meta:
        description = "Phishing Kit impersonating LIDL"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2025-02-16"
        comment = "Phishing Kit - LIDL - using ninja.jpg file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "index.php"
        $spec_file2 = "autocuisseur.jpg"
        $spec_file3 = "bouilloire.jpg"
        $spec_file4 = "lidl.png"
        $spec_file5 = "ninja.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
