rule PK_Gemini_claim : Gemini
{
    meta:
        description = "Phishing Kit impersonating Gemini"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-17"
        comment = "Phishing Kit - Gemini - 'Log in to Claim $200'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_dir2 = "aos"
        $spec_file1 = "login.php"
        $spec_file2 = "error.html"
        $spec_file3 = "verify.php"
        $spec_file4 = "gemini-phone.mp4"
        $spec_file5 = "free-money.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
