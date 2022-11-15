rule PK_Correos_264 : Correos
{
    meta:
        description = "Phishing Kit impersonating Correos"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1591896342502297602"
        date = "2022-11-13"
        comment = "Phishing Kit - Correos - 'precio: 2,64 Euros' - backdoored kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Deliver"
        $spec_dir2 = "settings"
        $spec_file1 = "Detalles_del_pago.php"
        $spec_file2 = "Recibir_paquete.php"
        $spec_file3 = "sms.php"
        $spec_file4 = "Cargando.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
