rule PK_Square_RD971 : Square
{
    meta:
        description = "Phishing Kit impersonating Square"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-08"
        comment = "Phishing Kit - Square - RD971"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "thank.html"
        $spec_file2 = "email.php"
        $spec_file3 = "em.html"
        $spec_file4 = "brand.css"
        $spec_file5 = "logo.svg"
        $spec_file6 = "next.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}