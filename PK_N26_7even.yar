rule PK_N26_7even : N26
{
    meta:
        description = "Phishing Kit impersonating N26"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-11"
        comment = "Phishing Kit - N26 - 'Main Author: 7EVEN'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Gaurd"
        $spec_dir2 = "app"
        $spec_dir3 = "n26_files"
        // specific file found in PhishingKit
        $spec_file = "inco.php"
        $spec_file2 = "key1.php"
        $spec_file3 = "pin4.php"
        $spec_file4 = "visitors.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
