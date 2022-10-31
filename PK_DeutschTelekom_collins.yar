rule PK_DeutschTelekom_collins : DeutschTelekom
{
    meta:
        description = "Phishing Kit impersonating DeutschTelekom - T Online"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1584832648035303425"
        date = "2022-10-25"
        comment = "Phishing Kit - DeutschTelekom - T Online - use filenames like 'collins'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "collins.php"
        $spec_file2 = "toline.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
