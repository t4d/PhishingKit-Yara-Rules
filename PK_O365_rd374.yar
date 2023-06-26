rule PK_O365_rd374 : Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-23"
        comment = "Phishing Kit - Office 365 - RD374"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "js"
        $spec_dir1 = "images"
        $spec_file1 = "email.php"
        $spec_file2 = "next.php"
        $spec_file3 = "bg.jpg"
        $spec_file4 = "index.html"
        $spec_file5 = "picker_account_msa.svg"
        $spec_file6 = "0.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
