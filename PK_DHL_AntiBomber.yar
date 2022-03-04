rule PK_DHL_AntiBomber : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-02-27"
        comment = "Phishing Kit - DHL - 'AntiBomber DHL' - 'Template Version : V.1.1'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "layout"
        $spec_file1 = "to.php"
        $spec_file2 = "210b.html"
        $spec_file3 = "request.php"
        $spec_file4 = "test.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
