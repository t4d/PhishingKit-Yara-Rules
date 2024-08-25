rule PK_StandardBank_bcc : Standard_Bank
{
    meta:
        description = "Phishing Kit impersonating Standard Bank Online Banking"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-23"
        comment = "Phishing Kit - Standard Bank - email with BCC header"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "audio"
        $spec_dir2 = "php"
        $spec_dir3 = "logs"
        $spec_file1 = "ph.php"
        $spec_file2 = "cc.html"
        $spec_file3 = "otp.js"
        $spec_file4 = "fnbringbacktone.mp3"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
