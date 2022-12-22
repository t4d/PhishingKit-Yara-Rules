rule PK_IsraelPost_gcs : IsraelPost
{
    meta:
        description = "Phishing Kit impersonating Israel Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-03"
        comment = "Phishing Kit - Israel Post - 'GcS-Team isreal Post'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "app"
        $spec_dir1 = "files"
        // specific files found in PhishingKit
        $spec_file1 = "sms.php"
        $spec_file2 = "sendbank.php"
        $spec_file3 = "vbvmcs.png"
        $spec_file4 = "step2.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
