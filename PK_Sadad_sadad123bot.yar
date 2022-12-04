rule PK_Sadad_sadad123bot : Sadad
{
    meta:
        description = "Phishing Kit impersonating Sadad"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-04"
        comment = "Phishing Kit - Sadad - 'name of TG bot: Sadad123Bot'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "banks"
        $spec_dir2 = "img-bank"
        $spec_file1 = "jazira.php"
        $spec_file2 = "usr.php"
        $spec_file3 = "deta.php"
        $spec_file4 = "sadad_logo_ar.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
