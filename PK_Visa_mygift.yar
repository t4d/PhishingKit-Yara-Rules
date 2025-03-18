rule PK_Visa_mygift : Visa
{
    meta:
        description = "Phishing Kit impersonating Visa"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-18"
        comment = "Phishing Kit - Visa - 'MyGift Visa Gift Card"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "mygift"
        $spec_dir2 = "generic-cards"
        $spec_file1 = "server.php"
        $spec_file2 = "mygift-hero-1200.a15c1f6d48f64cdc.webp"
        $spec_file3 = "v1.7-38.js"
        $spec_file4 = "visa-virtual-account-banner.b17c109d96a31f17.webp"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
