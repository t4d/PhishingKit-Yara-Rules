rule PK_GLS_dk : GLS
{
    meta:
        description = "Phishing Kit impersonating GLS Denmark"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-21"
        comment = "Phishing Kit - GLS - '<title>GLS Denmark</title>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_dir2 = "report"
        $spec_file1 = "reembolso.php"
        $spec_file2 = "mpanel.html"
        $spec_file3 = "copy.html"
        $spec_file4 = "null.png"
        $spec_file5 = "Capture.JPG"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
