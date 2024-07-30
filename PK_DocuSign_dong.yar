rule PK_DocuSign_dong : DocuSign
{
    meta:
        description = "Phishing Kit impersonating DocuSign"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-25"
        comment = "Phishing Kit - DocuSign - 'From: WEBMIL-ACCESS <dong202@gmail.com>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ab"
        $spec_dir2 = "dashboard"
        $spec_file1 = "app.js"
        $spec_file2 = "result.php"
        $spec_file3 = "config.php"
        $spec_file4 = "webmailout.png"
        $spec_file5 = "othermail.ico"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
