rule PK_Gandi_jp : Gandi
{
    meta:
        description = "Phishing Kit impersonating Gandi"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-23"
        comment = "Phishing Kit - Gandi - '(JP-Hack | gandi.net |)'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        $spec_file1 = "login1.php"
        $spec_file2 = "roundcube_logo.png"
        $spec_file3 = "jstz.js"
        $spec_file4 = "index.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}