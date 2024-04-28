rule PK_XFinity_devops : XFinity
{
    meta:
        description = "Phishing Kit impersonating XFinity"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-10"
        comment = "Phishing Kit - XFinity - '$_POST[name] = Devops'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Sign in to Xfinity_files"
        $spec_dir2 = "password"

        $spec_file1 = "action.php"
        $spec_file2 = "dest5.html"
        $spec_file3 = "index11.html"
        $spec_file4 = "img.html"
        $spec_file5 = "img.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
