rule PK_FirstNationalBank_verification : FirstNationalBank
{
    meta:
        description = "Phishing Kit impersonating First National Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-13"
        comment = "Phishing Kit - First National Bank - multiple 'verification' files"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directories found in PhishingKit
        $spec_dir = "Online Banking_files"
        $spec_dir1 = "ebucks-rewards_files"
        // specific file found in PhishingKit
        $spec_file = "verification_55.php"
        $spec_file2 = "tick.JPG"
        $spec_file3 = "activityi.html"
        $spec_file4 = "phone-verification.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
