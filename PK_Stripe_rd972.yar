rule PK_Stripe_rd972 : Stripe
{
    meta:
        description = "Phishing Kit impersonating Stripe"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-31"
        comment = "Phishing Kit - Stripe - stripe-RD972"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "css"
        $spec_dir2 = ".git"
        $spec_file1 = "confirm.html"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "login.531530f676cc5cd496ce.css"
        $spec_file5 = "thank.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
