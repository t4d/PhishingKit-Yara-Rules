rule PK_YahooMail_x2 : YahooMail
{
    meta:
        description = "Phishing Kit impersonating Yahoo Mail"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-25"
        comment = "Phishing Kit - Yahoo Mail - 'x2.php file'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "script"
        // specific file found in PhishingKit
        $spec_file = "x2.php"
        $spec_file2 = "home.html"
        $spec_file3 = "cont.php"
        $spec_file4 = "yahoo_en-US_f_p_bestfit_2x.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}
