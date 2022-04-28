rule PK_Amazon_rd292 : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-14-08"
        comment = "Phishing Kit - Amazon.fr - 'CrEaTeD bY VeNzA' - zipfile with RD292 reference"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir1 = "images"
        $spec_file1 = "em.html"
        $spec_file2 = "detail.html"
        $spec_file3 = "email.php"
        $spec_file4 = "thank.html"
        $spec_file5 = "card.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}