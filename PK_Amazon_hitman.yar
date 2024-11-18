rule PK_Amazon_hitman : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-11"
        comment = "Phishing Kit - Amazon - 'Coded & Tools By Hitman'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files_billing2"
        $spec_dir1 = "content"
        $spec_dir2 = "img"
        $spec_file1 = "Help.php"
        $spec_file2 = "script-login-mobile.js"
        $spec_file3 = "action_page_2.php"
        $spec_file4 = "cc-lRj.png"
        $spec_file5 = "amazon_logo_no-org_mid._V153387053_.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
