rule PK_Aruba_arduino : Aruba
{
    meta:
        description = "Phishing Kit impersonating Aruba S.p.A."
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-03"
        comment = "Phishing Kit - Aruba - 'ARDUINO_DAS ARUBA(Login) V.4'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "send"
        $spec_dir2 = "de"
        $spec_file1 = "ura.php"
        $spec_file2 = "billy.php"
        $spec_file3 = "indexo.php"
        $spec_file4 = "email.php"
        $spec_file5 = "ARDUINO_DAS_VISIT.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
