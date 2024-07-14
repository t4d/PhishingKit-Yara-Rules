rule PK_TexomaCU_prohqcker : TexomaCU
{
    meta:
        description = "Phishing Kit impersonating Texoma Community Credit Union "
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-12"
        comment = "Phishing Kit - TexomaCU - '**Prohqcker*TC***+++'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "file"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "me.php"
        $spec_file2 = "c.html"
        $spec_file3 = "prohqcker3.php"
        $spec_file4 = "personal.html"
        $spec_file5 = "logo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
