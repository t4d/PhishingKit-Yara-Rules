rule PK_AXA_m3tri : AXA
{
    meta:
        description = "Phishing Kit impersonating AXA insurance"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-17"
        comment = "Phishing Kit - AXA - 'Coded by METRI'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "M3tri-hash-bots"
        $spec_dir2 = "Xa_files"
        // specific file found in PhishingKit
        $spec_file = "Xa-infos.php"
        $spec_file2 = "cn-ajax.php"
        $spec_file3 = "infos.js"
        $spec_file4 = "PMT.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
