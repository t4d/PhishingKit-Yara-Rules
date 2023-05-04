rule PK_AXA_fun : AXA
{
    meta:
        description = "Phishing Kit impersonating AXA banque"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-02"
        comment = "Phishing Kit - AXA - using a fun.php page"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "detail.html"
        $spec_file2 = "fun.php"
        $spec_file3 = "fin.html"
        $spec_file4 = "axa_pp_blanc.min.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
