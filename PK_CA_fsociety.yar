rule PK_CA_fsociety : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/posts/stalkphish_phishing-phishingkit-scam-activity-7020324104964579328-B4ui?utm_source=share&utm_medium=member_desktop"
        date = "2023-01-15"
        comment = "Phishing Kit - Credit Agricole - 'C0d3d by fS0C13TY_Team'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "style"
        $spec_dir2 = "system"
        $spec_file0 = "email_securipass.php"
        $spec_file1 = "Wait_forte.php"
        $spec_file2 = "admin.php"
        $spec_file3 = "TelegramApi.php"
        $spec_file4 = "CADIF_logo_horizontal_rvb_v4.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
