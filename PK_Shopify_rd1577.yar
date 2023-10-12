rule PK_Shopify_rd1577 : Shopify
{
    meta:
        description = "Phishing Kit impersonating Shopify"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-12"
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
        $spec_file3 = "em.html"
        $spec_file4 = "logo.svg"
        $spec_file5 = "merchant-public-74905ef98de85e0ffeaf97e73e3acecf947ca5834def49b15c5cb54ddc6323ce.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
