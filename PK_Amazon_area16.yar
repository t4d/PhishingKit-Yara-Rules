rule PK_Amazon_area16 : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-13"
        comment = "Phishing Kit - Amazon - AREA16 directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "AREA16"
        $spec_dir1 = "admin"
        $spec_dir2 = "application"
        $spec_file1 = ".htaccess"
        $spec_file2 = "Oauth.php"
        $spec_file3 = "license.ini"
        $spec_file4 = "setting.json"
        $spec_file5 = "mobile2.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
