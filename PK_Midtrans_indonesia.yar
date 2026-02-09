rule PK_Midtrans_indonesia : Midtrans
{
    meta:
        description = "Phishing Kit impersonating Midtrans"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-01-21"
        comment = "Phishing Kit - Midtrans"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "midtrans-php"
        $spec_dir2 = "foto"

        // specific file found in PhishingKit
        $spec_file = "koneksi.php"
        $spec_file2 = "config_midtrans.php"
        $spec_file3 = "log_midtrans.txt"
        $spec_file4 = "login_pembeli.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_file*) and
        all of ($spec_dir*)
}
