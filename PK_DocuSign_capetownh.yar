rule PK_DocuSign_capetownh : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-01-10"
        comment = "Phishing Kit - DocuSign - 'capetownh.txt'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "javascript"
        $spec_file1 = "u.php"
        $spec_file2 = "hello.php"
        $spec_file3 = "php.ini"
        $spec_file4 = "facebox.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
