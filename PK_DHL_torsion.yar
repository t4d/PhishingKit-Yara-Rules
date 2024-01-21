rule PK_DHL_torsion : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-09"
        comment = "Phishing Kit - DHL - using a 'torsion' directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "torsion"
        $spec_dir2 = "pages"
        $spec_file1 = "config4.php"
        $spec_file2 = "sms2.php"
        $spec_file3 = "ico3 - zz.svg"
        $spec_file4 = "dhl-logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
