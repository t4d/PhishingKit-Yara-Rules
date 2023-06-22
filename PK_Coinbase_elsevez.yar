rule PK_Coinbase_elsevez : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-15"
        comment = "Phishing Kit - Coinbase - 'info@res.elsevezapp.com'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "statistics"
        $spec_dir2 = "elsevezpro"
        // specific files found in PhishingKit
        $spec_file1 = "app.js"
        $spec_file2 = "password_reset.css"
        $spec_file3 = "payment.txt"
        $spec_file4 = "coins-bbf90d20400a2fc88309b880c84c0b83f50d6307df9add13302b1f9e28fe64f5.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
