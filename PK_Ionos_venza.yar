rule PK_Ionos_venza : Ionos
{
    meta:
        description = "Phishing Kit impersonating Ionos"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-21"
        comment = "Phishing Kit - Ionos - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        $spec_dir2 = "ionospassword_files"
        $spec_file1 = "ionospassword.html"
        $spec_file2 = "pass.php"
        $spec_file3 = "identifier.svg"
        $spec_file4 = "ionos.min.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
