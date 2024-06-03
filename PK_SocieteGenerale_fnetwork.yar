rule PK_SocieteGenerale_fnetwork : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-04-29"
        comment = "Phishing Kit - Societe Generale - 'BY Mr.fnetwork'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "files"
        $spec_dir1 = "img"
        $spec_dir2 = "js"
        $spec_file1 = "tel.php"
        $spec_file2 = "red.php"
        $spec_file3 = "scripts.js"
        $spec_file4 = "vide.gif"
        $spec_file5 = "merci.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
