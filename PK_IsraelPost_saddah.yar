rule PK_IsraelPost_saddah : IsraelPost
{
    meta:
        description = "Phishing Kit impersonating Israel Post"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-23"
        comment = "Phishing Kit - Israel Post - name of TG bot: 'saddah'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "inc"
        // specific files found in PhishingKit
        $spec_file1 = "spy.php"
        $spec_file2 = "main.php"
        $spec_file3 = "index22.php"
        $spec_file4 = "aramex-logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
