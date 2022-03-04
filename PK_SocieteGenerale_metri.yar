rule PK_SocieteGenerale_metri : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-09"
        comment = "Phishing Kit - Societe Generale - '/== SG LOG By METRI==/'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "M3tri-hash-bots"
        $spec_dir1 = "Soc_files"
        $spec_file1 = "defender.php"
        $spec_file2 = "Soc-infos.php"
        $spec_file3 = "Soc-log.php"
        $spec_file4 = "Error.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

