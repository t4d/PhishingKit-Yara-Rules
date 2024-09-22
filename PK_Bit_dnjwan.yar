rule PK_Bit_dnjwan : Bit
{
    meta:
        description = "Phishing Kit impersonating bitpay.co.il"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-02"
        comment = "Phishing Kit - Bit - by 'dnjwan'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "prevents"
        $spec_dir2 = "sms_files"
        $spec_file1 = "tlgrm.php"
        $spec_file2 = "step3.php"
        $spec_file3 = "load2.php"
        $spec_file4 = "sms2.php"
        $spec_file5 = "otp.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
