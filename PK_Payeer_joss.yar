rule PK_Payeer_joss : Payeer
{
    meta:
        description = "Phishing Kit impersonating Payeer"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-29"
        comment = "Phishing Kit - Payeer - 'joss.txt'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "PAYEER_files"
        // specific file found in PhishingKit
        $spec_file = "4.php"
        $spec_file2 = "Incorrect.html"
        $spec_file3 = "Incorrect-2fa.html"
        $spec_file4 = "enterprise.js.download"
        $spec_file5 = "saved_resource.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
