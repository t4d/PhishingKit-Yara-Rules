rule PK_MBHBank_takare : MBHBank
{
    meta:
        description = "Phishing Kit impersonating MBH Bank from Hungary"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-12"
        comment = "Phishing Kit - MBHBank - 'Takare Login'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mkb"
        $spec_dir2 = "takare"
        // specific file found in PhishingKit
        $spec_file = "node.html"
        $spec_file2 = "kod.html"
        $spec_file3 = "spin.html"
        $spec_file4 = "kartya_exMKB_netbank.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
