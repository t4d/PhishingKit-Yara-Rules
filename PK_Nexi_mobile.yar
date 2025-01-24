rule PK_Nexi_mobile : Nexi
{
    meta:
        description = "Phishing Kit impersonating Nexi (Nexi Pay)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-24"
        comment = "Phishing Kit - Nexi"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "pannello2"
        $spec_dir2 = "database"
        // specific file found in PhishingKit
        $spec_file = "carta.php"
        $spec_file2 = "key6.php"
        $spec_file3 = "ajaxstat.php"
        $spec_file4 = "VendorsTest_tmp.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
