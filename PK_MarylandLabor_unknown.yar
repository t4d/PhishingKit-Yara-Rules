rule PK_MarylandLabor_unknown : MaylandLabor
{
    meta:
        description = "Phishing Kit impersonating labor.maryland.gov"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-19"
        comment = "Phishing Kit - MaylandLabor - '-- unknown --'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_file1 = "email.php"
        $spec_file2 = "rzlt1.php"
        $spec_file3 = "em.html"
        $spec_file4 = "detail.html"
        $spec_file5 = "MA_Header_top.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}