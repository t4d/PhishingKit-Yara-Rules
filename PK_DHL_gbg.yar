rule PK_DHL_gbg : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-14"
        comment = "Phishing Kit - DHL - 'From: GEt-Back-Gang'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "7629827763"
        $spec_file1 = "log1234567.php"
        $spec_file2 = "index2.php"
        $spec_file3 = "log2345678.php"
        $spec_file4 = "1618379409484992.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
