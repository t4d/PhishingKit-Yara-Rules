rule PK_DocuSign_lexx : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-29"
        comment = "Phishing Kit - DocuSign - '-+ All Email Account! by lexx +-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_dir2 = "js"
        $spec_file1 = "lexx.php"
        $spec_file2 = "phn.php"
        $spec_file3 = "serverbusy.php"
        $spec_file4 = "phone.php"
        $spec_file5 = "office365logo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
