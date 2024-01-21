rule PK_CarrefourBanque_dx1 : CarrefourBanque
{
    meta:
        description = "Phishing Kit impersonating Carrefour Banque"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-12-03"
        comment = "Phishing Kit - CarrefourBanque - 'DX1 - CRF'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "config"
        $spec_dir2 = "css"
        $spec_dir3 = "js"

        $spec_file0 = "index.html"
        $spec_file1 = "init.js"
        $spec_file2 = "robot.txt"
        $spec_file3 = "807.89c8f7f9.js"
        $spec_file4 = "925.7ed9415b.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
