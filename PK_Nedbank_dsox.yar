rule PK_Nedbank_dsox : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-17"
        comment = "Phishing Kit - Nedbank - 'Coded By Dsox DZ'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "enforcer"
        $spec_dir2 = "spox"
        // specific file found in PhishingKit
        $spec_file = "post2.php"
        $spec_file2 = "blocked.txt"
        $spec_file3 = "rbots.php"
        $spec_file4 = "NedbankExperience.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
        all of ($spec_dir*)
}
