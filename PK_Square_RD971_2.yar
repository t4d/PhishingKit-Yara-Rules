rule PK_Square_RD971_2 : Square
{
    meta:
        description = "Phishing Kit impersonating Square"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-10"
        comment = "Phishing Kit - Square - RD971 (2024 new)"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_dir2 = "hooks"
        $spec_dir3 = "css"
        $spec_file1 = "index.html"
        $spec_file2 = "email.php"
        $spec_file3 = "otp.html"
        $spec_file4 = "brand.css"
        $spec_file5 = "logo.svg"
        $spec_file6 = "next.php"
        $spec_file7 = "load.gif"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
