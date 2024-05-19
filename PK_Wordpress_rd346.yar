rule PK_Wordpress_rd346 : Wordpress
{
    meta:
        description = "Phishing Kit impersonating Wordpress.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-18"
        comment = "Phishing Kit - Wordpress - RD346"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "index.html"
        $spec_file1 = "detail.html"
        $spec_file2 = "next.php"
        $spec_file4 = "powered-by-jetpack.svg"
        $spec_file5 = "entry-login.bc4450552965f155cb31.min.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
