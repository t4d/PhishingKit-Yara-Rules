rule PK_Paypal_RD304 : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-03"
        comment = "Phishing Kit - Paypal - RD304"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "img"
        $spec_dir2 = "css"
        $spec_file1 = "index.html"
        $spec_file2 = "email.php"
        $spec_file3 = "PayPalSansBig-Regular.woff"
        $spec_file4 = "vbv_2.css"
        $spec_file5 = "pp64.png"
        $spec_file6 = "next.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
