rule PK_Caixa_z0n51 : Caixa
{
    meta:
        description = "Phishing Kit impersonating Caixa Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-16"
        comment = "Phishing Kit - Caixa Bank - 'Main Author: EL GH03T && Z0N51'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "includes"
        $spec_dir1 = "cc_files"
        $spec_file1 = "defender.php"
        $spec_file2 = "404.php"
        $spec_file3 = "visitors.html"
        $spec_file4 = "_responsive.scss"
        $spec_file5 = "mobile2.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
