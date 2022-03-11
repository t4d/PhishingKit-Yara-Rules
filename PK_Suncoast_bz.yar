rule PK_Suncoast_bz : Suncoast
{
    meta:
        description = "Phishing Kit impersonating Suncoast Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-06"
        comment = "Phishing Kit - Suncoast - '$to = resultbox@suncoast.bz'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "surf4.php"
        $spec_file2 = "st.gif"
        $spec_file3 = "s11.png"
        $spec_file4 = "email.php"
        $spec_file4 = "need3.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
