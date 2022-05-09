rule PK_Excel_xls : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-13"
        comment = "Phishing Kit - Excel - 'From: XLS'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "go.php"
        $spec_file2 = "po.html"
        $spec_file3 = "xls.php"
        $spec_file4 = "server.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}