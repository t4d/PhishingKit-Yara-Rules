rule PK_Amazon_ghayt : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-25"
        comment = "Phishing Kit - Amazon - 'ghayt_Zone'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "anti__boot"
        $spec_dir1 = "js"
        $spec_file1 = "loading3.php"
        $spec_file2 = "visitors.html"
        $spec_file3 = "password.php"
        $spec_file4 = "test.css"
        $spec_file5 = "secure.png"
        $spec_file6 = "detect.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
