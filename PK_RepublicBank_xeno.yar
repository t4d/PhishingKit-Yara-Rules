rule PK_RepublicBank_xeno : RepublicBank
{
    meta:
        description = "Phishing Kit impersonating RepublicBank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-10"
        comment = "Phishing Kit - RepublicBank - '| By Xeno |'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "blackhole"
        // specific file found in PhishingKit
        $spec_file = "loading1.php"
        $spec_file2 = "otp1.php"
        $spec_file3 = "auth.php"
        $spec_file4 = "blackhole.dat"
        $spec_file5 = "logo_positivo_login-big.d0676c56ea8632b469ad.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
