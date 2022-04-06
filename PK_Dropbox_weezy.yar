rule PK_Dropbox_weezy : Dropbox
{
    meta:
        description = "Phishing Kit impersonating Dropbox"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-05"
        comment = "Phishing Kit - Dropbox - '-By Weezy-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "asset"
        $spec_file1 = "block.php"
        $spec_file2 = "login.html"
        $spec_file3 = "process.php"
        $spec_file4 = "dropbox_logo_glyph_2015-vfl4ZOqXa.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
