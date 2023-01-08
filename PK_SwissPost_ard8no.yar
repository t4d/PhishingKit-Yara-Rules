rule PK_SwissPost_ard8no : SwissPost
{
    meta:
        description = "Phishing Kit impersonating Swiss Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-08"
        comment = "Phishing Kit - Swiss Post - 'From: [ARD8NO_DAS **]<info@arduino.com>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Redsys_files"
        $spec_dir2 = "Venta_fichiers"
        $spec_dir3 = "rez"
        // specific file found in PhishingKit
        $spec_file = "pay.php"
        $spec_file2 = "laoding2.php"
        $spec_file3 = "POST.svg"
        $spec_file4 = "deutsche.png"
        $spec_file5 = "reperrsms.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
