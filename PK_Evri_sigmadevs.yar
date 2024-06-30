rule PK_Evri_sigmadevs : Evri
{
    meta:
        description = "Phishing Kit impersonating Evri"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/feed/update/urn:li:activity:7196747706084610049"
        date = "2024-05-16"
        comment = "Phishing Kit - Evri - 'AUTHORS/CODERS : S3IKO && J33H4N @ SIGMADEVS"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "bots"
        $spec_dir2 = "post"
        // specific file found in PhishingKit
        $spec_file = "653334efe4c59-59842.php"
        $spec_file2 = "send.php"
        $spec_file3 = "cv.js"
        $spec_file4 = "out.php"
        $spec_file5 = "vbvmcs.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
