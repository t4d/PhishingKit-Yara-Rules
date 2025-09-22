rule PK_Netflix_logofeveryt : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-12"
        comment = "Phishing Kit - Netflix - 'by_logofeveryt'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_file = "telegram-submit.js"
        $spec_file2 = "payment.js"
        $spec_file3 = "BrandAssets_Logos_01-Wordmark.jpg"
        $spec_file4 = "the_netflix_login_background__canada__2024___by_logofeveryt_dh0w8qv-pre.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_file*)
}
