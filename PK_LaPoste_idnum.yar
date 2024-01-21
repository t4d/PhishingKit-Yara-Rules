rule PK_LaPoste_idnum : LaPoste
{
    meta:
        description = "Phishing Kit impersonating La Poste FR - identite numerique"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-14"
        comment = "Phishing Kit - LaPoste - identite numerique"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "act"
        // specific file found in PhishingKit
        $spec_file = "rs.txt"
        $spec_file2 = "refresh.php"
        $spec_file3 = "zbs.php"
        $spec_file4 = "getphone.php"
        $spec_file5 = "info.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
