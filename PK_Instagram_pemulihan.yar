rule PK_Instagram_pemulihan : Instagram
{
    meta:
        description = "Phishing Kit impersonating Instagram"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-10"
        comment = "Phishing Kit - Instagram - found in a directory named 'pemulihan'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "cgi-bin"
        $spec_dir2 = "images"
        $spec_file1 = "chatId.php"
        $spec_file2 = "app.js"
        $spec_file3 = "wrong.php"
        $spec_file4 = "ehe.jpeg"
        $spec_file5 = "code.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
