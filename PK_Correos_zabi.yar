rule PK_Correos_zabi : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-03"
        comment = "Phishing Kit - Correos - use of file called 'zabi_la_dezti.php'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Venta_fichiers"
        $spec_file1 = "zabi_la_dezti.php"
        $spec_file2 = "codeerror2.php"
        $spec_file3 = "Seleccione_gracias.php"
        $spec_file4 = "sys.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}