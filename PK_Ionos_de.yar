rule PK_Ionos_de : Ionos
{
    meta:
        description = "Phishing Kit impersonating Ionos"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-09"
        comment = "Phishing Kit - Ionos - targeting DE users"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "files"
        $spec_file1 = "login.html"
        $spec_file2 = "post.php"
        $spec_file3 = "postt.php"
        $spec_file4 = "ionos.min.css"
        $spec_file5 = "pass.html"
        $spec_file6 = "70000.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
