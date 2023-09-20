rule PK_Adobe_RD2 : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe "
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-06"
        comment = "Phishing Kit - Adobe - 'cReAtEd By VeNzA'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "index.html"
        $spec_file4 = "adobe1.png"
        $spec_file5 = "adobe1-w.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
