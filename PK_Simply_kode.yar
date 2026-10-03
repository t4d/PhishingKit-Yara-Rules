rule PK_Simply_kode : simply
{
    meta:
        description = "Phishing Kit impersonating simply.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-28"
        comment = "Phishing Kit - simply.com - 'personal_kode'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "auth"
        $spec_dir2 = "panel"
        // specific file found in PhishingKit
        $spec_file = "alert.php"
        $spec_file2 = "password.php"
        $spec_file3 = "png_f528764d624db129b32c21fbca0cb8d6"
        $spec_file4 = "users.json"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
