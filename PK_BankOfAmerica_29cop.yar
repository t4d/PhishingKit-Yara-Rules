rule PK_BankOfAmerica_29cop : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-30"
        comment = "Phishing Kit - BankOfAmerica - 'From: Reporte_29COP'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Bank of America _ Banca en Línea _ Entrar _ Identificación en línea_files"
        $spec_dir2 = "paso4_files"
        $spec_dir3 = "img"
        // specific file found in PhishingKit
        $spec_file = "tuc0rre0.php"
        $spec_file2 = "ant.php"
        $spec_file3 = "funciones.js.descarga"
        $spec_file4 = "porteja.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
