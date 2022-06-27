rule PK_Aruba_RD72 : Aruba
{
    meta:
        description = "Phishing Kit impersonating Aruba S.p.A."
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-21"
        comment = "Phishing Kit - Aruba - RD72 - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "email.php"
        $spec_file2 = "aruba-promo.jpg"
        $spec_file3 = "login.css"
        $spec_file4 = "next.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
