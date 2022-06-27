rule PK_DeutschTelekom_dea0006 : DeutschTelekom
{
    meta:
        description = "Phishing Kit impersonating DeutschTelekom - T Online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-21"
        comment = "Phishing Kit - DeutschTelekom - T Online - 'T-ONLINE.DEA0006'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "confir.php"
        $spec_file2 = "loading.htm"
        $spec_file3 = "redirect1.php"
        $spec_file4 = "serverbusy.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
