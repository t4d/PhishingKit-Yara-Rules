rule PK_NAB_otp : NAB
{
    meta:
        description = "Phishing Kit impersonating National Australia Bank (NAB)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-22"
        comment = "Phishing kit - NAB - retrieve OTP"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "post"
        // specific file found in PhishingKit
        $spec_file = "otp1.php"
        $spec_file2 = "antiip.php"
        $spec_file3 = "resms.php"
        $spec_file4 = "timer.php"
        $spec_file5 = "loading-25.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
