rule PK_Eika_oio : Eika
{
    meta:
        description = "Phishing Kit impersonating Eika Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-10-01"
        comment = "Phishing Kit - Eika - using oio files"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "BankID_fichiers"
        spec_dir2 = "src"
        // specific file found in PhishingKit
        $spec_file = "oio.php"
        $spec_file2 = "index33.html"
        $spec_file3 = "oio5.php"
        $spec_file4 = "Bekreftelseeee.htm"
        $spec_file5 = "eika_logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
