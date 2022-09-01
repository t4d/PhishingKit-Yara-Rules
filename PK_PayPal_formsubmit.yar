rule PK_PayPal_formsubmit : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1565010550488276993"
        date = "2022-08-31"
        comment = "Phishing Kit - PayPal - using formsubmit platform"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file1 = "app.js"
        $spec_file2 = "index.html"
        $spec_file3 = "momgram@2x.png"
        $spec_file4 = "style.css"
        $spec_file5 = "warning.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_file*)
}
