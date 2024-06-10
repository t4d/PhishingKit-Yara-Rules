rule PK_Postbank_buff : Postbank
{
    meta:
        description = "Phishing Kit impersonating Postbank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-06-04"
        comment = "Phishing Kit - Postbank - 'ini_set(output_buffering,4096)'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Postbank Banking & Brokerage-Dateien"
        $spec_dir1 = "danke-Dateien"
        $spec_dir2 = "BOTS"
        // specific file found in PhishingKit
        $spec_file = "Postbank Banking & Brokerage.htm"
        $spec_file2 = "passwort.php"
        $spec_file3 = "params.php"
        $spec_file4 = "ccadd.php"
        $spec_file5 = "pbbg.94a99b13acbdc92b.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
