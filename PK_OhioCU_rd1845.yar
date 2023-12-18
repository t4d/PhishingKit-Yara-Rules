rule PK_OhioCU_rd1845 : OhioCU
{
    meta:
        description = "Phishing Kit impersonating Credit Union of Ohio"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-01"
        comment = "Phishing Kit - OhioCU - RD1845"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file = "detail.html"
        $spec_file2 = "next.php"
        $spec_file3 = "styles.be58d74c85678e20.css"
        $spec_file4 = "cuoo-landing.jpg"

    condition:
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
