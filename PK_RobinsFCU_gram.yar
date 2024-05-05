rule PK_RobinsFCU_gram : RobinsFCU
{
    meta:
        description = "Phishing Kit impersonating Robins Financial Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-05"
        comment = "Phishing Kit - RobinsFCU - 'using $Gram variable name'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directories found in PhishingKit
        $spec_dir = "Assets"
        $spec_dir1 = "user"
        // specific file found in PhishingKit
        $spec_file = "verifylogin.php"
        $spec_file2 = "process1.php"
        $spec_file3 = "ServerData.php"
        $spec_file4 = "edit.php"
        $spec_file5 = "FraudAlertsPanelImages.png.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
