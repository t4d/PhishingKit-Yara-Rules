rule PK_Shaw_aeroplan : Shaw
{
    meta:
        description = "Phishing Kit impersonating Shaw.ca"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-03-08"
        comment = "Phishing Kit - Shaw - redirect to aeroplan"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "shaw"
        $spec_dir2 = "successfully"
        // specific file found in PhishingKit
        $spec_file = "index_login.html"
        $spec_file2 = "aeroplan-logo.svg"
        $spec_file3 = "form1.php"
        $spec_file4 = "radio-jazz-online24.png"
        $spec_file5 = "icomoond41d.eot"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
