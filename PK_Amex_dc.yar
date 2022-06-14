rule PK_Amex_dc : Amex
{
    meta:
        description = "Phishing Kit impersonating American Express"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-14"
        comment = "Phishing Kit - Amex - '- DC -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        $spec_dir2 = "images"
        $spec_file1 = "email.php"
        $spec_file2 = "thanks.php"
        $spec_file3 = "emaiinfo_error.html"
        $spec_file4 = "20-AMX-0046_Covid19Support-AmexBanner_300x250_m01_46.jpg"
        $spec_file5 = "4.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}