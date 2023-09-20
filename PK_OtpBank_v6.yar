rule PK_OtpBank_v6 : OtpBank
{
    meta:
        description = "Phishing Kit impersonating OtpBank (OTP Direkt)"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-00-09"
        comment = "Phishing Kit - OtpBank - 'otbbank-v6'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "api"
        $spec_dir3 = "loading"
        $spec_file = "4.php"
        $spec_file2 = "sms-error.php"
        $spec_file3 = "Thanks.php"
        $spec_file4 = "TRAFFIC.TXT"
        $spec_file5 = "OTP-icon-72x72-search-user.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        // check for files
        all of ($spec_file*)
}
