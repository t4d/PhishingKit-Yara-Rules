rule PK_Intesa_ghayt : Intesa
{
    meta:
        description = "Phishing Kit impersonating Intesa Sanpaolo"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-23"
        comment = "Phishing Kit - Intesa - '@ghayt'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "pro"
        $spec_dir2 = "arq"
        // specific files found in PhishingKit
        $spec_file1 = "EloLgnB011000.js"
        $spec_file2 = "cc.php"
        $spec_file3 = "ci.php"
        $spec_file4 = "login-logo.el.png"
        $spec_file5 = "visitors.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
