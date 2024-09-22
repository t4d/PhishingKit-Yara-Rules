rule PK_USPS_vensuxv : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-20"
        comment = "Phishing Kit - USPS - 'vensuxv USPS Billing'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "5_files"
        $spec_dir2 = "Global Payment _ USPS_files"
        // specific file found in PhishingKit
        $spec_file = "laylay.css"
        $spec_file2 = "import smtplib.md"
        $spec_file3 = "genius8.php"
        $spec_file4 = "loading_end.php"
        $spec_file5 = "usps-theme.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
