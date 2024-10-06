rule PK_Shopify_rd1979 : Shopify
{
    meta:
        description = "Phishing Kit impersonating Shopify"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - Shopify - RD1577"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "acc.html"
        $spec_file2 = "next.php"
        $spec_file3 = "otp.html"
        $spec_file4 = "logo.svg"
        $spec_file5 = "merchant-public-b2b713b82cff21a7122558448c48f2d3b6c6d547b0ef6e80f9e43c33e7d43a82.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
