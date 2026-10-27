rule PK_Ledger_ekkne : Ledger
{
    meta:
        description = "Phishing Kit impersonating Ledger"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-10-05"
        comment = "Phishing Kit - Ledger - using 'Data_Ekkne.php' file"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Folder"
        $spec_dir2 = "led"
        $spec_file = "Data_Ekkne.php"
        $spec_file2 = "vaa_Info.php"
        $spec_file3 = "nanoPinCode-6MOVVJX5.png"
        $spec_file4 = "buyNanoX-D6R3F3RS.webm"
        $spec_file5 = "ledgerlogo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
