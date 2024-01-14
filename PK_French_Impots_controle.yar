rule PK_French_Impots_controle : impots_FR
{
    meta:
        description = "Phishing Kit impersonating French taxes portal"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-13"
        comment = "Phishing Kit - impots_FR - French taxes portal"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "12Remboursement_files"
        $spec_file = "cc.html"
        $spec_file2 = "sms-auth0.php.html"
        $spec_file3 = "sub5.php"
        $spec_file4 = "vérification du code en cours....html"
        $spec_file5 = "fermer.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
