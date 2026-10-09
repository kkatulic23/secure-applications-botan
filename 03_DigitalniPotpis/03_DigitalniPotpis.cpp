#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "SignatureApp.h"

namespace
{
    const std::string POTPISNA_SHEMA = "PSS(SHA-256)";
    const std::string PRIVATNI_KLJUC_DATOTEKA = "privatni_kljuc.pem";
    const std::string JAVNI_KLJUC_DATOTEKA = "javni_kljuc.pem";
    const std::string POTPISANI_TEKST_DATOTEKA = "potpisani_tekst.txt";
    const std::string POTPIS_TEKSTA_DATOTEKA = "potpis_teksta.sig";
    const std::string POTPIS_DATOTEKE_DATOTEKA = "potpis_datoteke.sig";

    std::string ucitajTekst(const std::string& poruka)
    {
        std::string tekst;
        std::cout << poruka;
        std::getline(std::cin, tekst);
        return tekst;
    }

    int ucitajOdabir()
    {
        int odabir = 0;
        std::cin >> odabir;

        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return -1;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return odabir;
    }

    std::string ocistiPutanju(std::string putanja)
    {
        if (putanja.size() >= 2)
        {
            bool imaDvostrukeNavodnike = putanja.front() == '"' && putanja.back() == '"';
            bool imaJednostrukeNavodnike = putanja.front() == '\'' && putanja.back() == '\'';

            if (imaDvostrukeNavodnike || imaJednostrukeNavodnike)
            {
                putanja = putanja.substr(1, putanja.size() - 2);
            }
        }

        return putanja;
    }

    void spremiTekstUDatoteku(const std::string& nazivDatoteke, const std::string& sadrzaj)
    {
        std::ofstream datoteka(nazivDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku za pisanje: " + nazivDatoteke);
        }

        datoteka << sadrzaj;
    }

    void spremiBinarnoUDatoteku(const std::string& nazivDatoteke, const std::vector<uint8_t>& sadrzaj)
    {
        std::ofstream datoteka(nazivDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku za pisanje: " + nazivDatoteke);
        }

        datoteka.write(reinterpret_cast<const char*>(sadrzaj.data()), sadrzaj.size());
    }

    std::string ucitajTekstIzDatoteke(const std::string& nazivDatoteke)
    {
        std::ifstream datoteka(nazivDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku za citanje: " + nazivDatoteke);
        }

        return std::string(
            std::istreambuf_iterator<char>(datoteka),
            std::istreambuf_iterator<char>()
        );
    }

    std::vector<uint8_t> ucitajBinarnoIzDatoteke(const std::string& nazivDatoteke)
    {
        std::ifstream datoteka(nazivDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku za citanje: " + nazivDatoteke);
        }

        return std::vector<uint8_t>(
            std::istreambuf_iterator<char>(datoteka),
            std::istreambuf_iterator<char>()
        );
    }

    void generirajKljuceve()
    {
        Botan::AutoSeeded_RNG generatorSlucajnihBrojeva;

        Botan::RSA_PrivateKey privatniKljuc(generatorSlucajnihBrojeva, 2048);
        std::unique_ptr<Botan::Public_Key> javniKljuc = privatniKljuc.public_key();

        std::string privatniKljucPem = Botan::PKCS8::PEM_encode(privatniKljuc);
        std::string javniKljucPem = Botan::X509::PEM_encode(*javniKljuc);

        spremiTekstUDatoteku(PRIVATNI_KLJUC_DATOTEKA, privatniKljucPem);
        spremiTekstUDatoteku(JAVNI_KLJUC_DATOTEKA, javniKljucPem);

        std::cout << "\nRSA par kljuceva je generiran.\n";
        std::cout << "Privatni kljuc spremljen je u: " << PRIVATNI_KLJUC_DATOTEKA << "\n";
        std::cout << "Javni kljuc spremljen je u: " << JAVNI_KLJUC_DATOTEKA << "\n";
    }

    std::vector<uint8_t> potpisiSadrzaj(const std::string& sadrzaj)
    {
        Botan::AutoSeeded_RNG generatorSlucajnihBrojeva;

        Botan::DataSource_Stream privatniKljucIzDatoteke(PRIVATNI_KLJUC_DATOTEKA);

        std::unique_ptr<Botan::Private_Key> privatniKljuc =
            Botan::PKCS8::load_key(privatniKljucIzDatoteke);

        Botan::PK_Signer potpisnik(*privatniKljuc, generatorSlucajnihBrojeva, POTPISNA_SHEMA);

        potpisnik.update(sadrzaj);

        return potpisnik.signature(generatorSlucajnihBrojeva);
    }

    bool provjeriPotpis(const std::string& sadrzaj, const std::vector<uint8_t>& potpis)
    {
        Botan::DataSource_Stream javniKljucIzDatoteke(JAVNI_KLJUC_DATOTEKA);

        std::unique_ptr<Botan::Public_Key> javniKljuc =
            Botan::X509::load_key(javniKljucIzDatoteke);

        Botan::PK_Verifier provjeritelj(*javniKljuc, POTPISNA_SHEMA);

        provjeritelj.update(sadrzaj);

        return provjeritelj.check_signature(potpis);
    }

    void potpisiTekst()
    {
        std::string tekst = ucitajTekst("\nUnesite tekst koji zelite digitalno potpisati: ");

        std::vector<uint8_t> potpis = potpisiSadrzaj(tekst);

        spremiTekstUDatoteku(POTPISANI_TEKST_DATOTEKA, tekst);
        spremiBinarnoUDatoteku(POTPIS_TEKSTA_DATOTEKA, potpis);

        std::cout << "\nTekst je digitalno potpisan.\n";
        std::cout << "Originalni tekst spremljen je u: " << POTPISANI_TEKST_DATOTEKA << "\n";
        std::cout << "Digitalni potpis spremljen je u: " << POTPIS_TEKSTA_DATOTEKA << "\n";

        std::cout << "\nPotpis u HEX obliku:\n";
        std::cout << Botan::hex_encode(potpis) << "\n";
    }

    void provjeriPotpisTeksta()
    {
        std::string tekst = ucitajTekst("\nUnesite tekst za provjeru potpisa: ");

        std::vector<uint8_t> potpis = ucitajBinarnoIzDatoteke(POTPIS_TEKSTA_DATOTEKA);

        bool potpisJeIspravan = provjeriPotpis(tekst, potpis);

        if (potpisJeIspravan)
        {
            std::cout << "\nPotpis je ispravan. Tekst nije promijenjen.\n";
        }
        else
        {
            std::cout << "\nPotpis nije ispravan. Tekst je promijenjen ili potpis ne odgovara.\n";
        }
    }

    void potpisiDatoteku()
    {
        std::string nazivDatoteke = ocistiPutanju(ucitajTekst("\nUnesite naziv datoteke koju zelite potpisati: "));

        std::string sadrzaj = ucitajTekstIzDatoteke(nazivDatoteke);
        std::vector<uint8_t> potpis = potpisiSadrzaj(sadrzaj);

        spremiBinarnoUDatoteku(POTPIS_DATOTEKE_DATOTEKA, potpis);

        std::cout << "\nDatoteka je digitalno potpisana.\n";
        std::cout << "Digitalni potpis spremljen je u: " << POTPIS_DATOTEKE_DATOTEKA << "\n";

        std::cout << "\nPotpis u HEX obliku:\n";
        std::cout << Botan::hex_encode(potpis) << "\n";
    }

    void provjeriPotpisDatoteke()
    {
        std::string nazivDatoteke = ocistiPutanju(ucitajTekst("\nUnesite naziv datoteke za provjeru potpisa: "));

        std::string sadrzaj = ucitajTekstIzDatoteke(nazivDatoteke);
        std::vector<uint8_t> potpis = ucitajBinarnoIzDatoteke(POTPIS_DATOTEKE_DATOTEKA);

        bool potpisJeIspravan = provjeriPotpis(sadrzaj, potpis);

        if (potpisJeIspravan)
        {
            std::cout << "\nPotpis je ispravan. Datoteka nije promijenjena.\n";
        }
        else
        {
            std::cout << "\nPotpis nije ispravan. Datoteka je promijenjena ili potpis ne odgovara.\n";
        }
    }

    void prikaziIzbornikPotpisa()
    {
        std::cout << "\n============================================\n";
        std::cout << "  APLIKACIJA ZA DIGITALNI POTPIS\n";
        std::cout << "============================================\n";
        std::cout << "1. Generiraj RSA kljuceve\n";
        std::cout << "2. Potpisi tekst\n";
        std::cout << "3. Provjeri potpis teksta\n";
        std::cout << "4. Potpisi datoteku\n";
        std::cout << "5. Provjeri potpis datoteke\n";
        std::cout << "0. Izlaz\n";
        std::cout << "Odabir: ";
    }
}

void PokreniAplikacijuDigitalnogPotpisa()
{
    while (true)
    {
        try
        {
            prikaziIzbornikPotpisa();
            int odabir = ucitajOdabir();

            switch (odabir)
            {
            case 1:
                generirajKljuceve();
                break;

            case 2:
                potpisiTekst();
                break;

            case 3:
                provjeriPotpisTeksta();
                break;

            case 4:
                potpisiDatoteku();
                break;

            case 5:
                provjeriPotpisDatoteke();
                break;

            case 0:
                std::cout << "Izlaz iz aplikacije.\n";
                return;

            default:
                std::cout << "Neispravan odabir. Pokusajte ponovno.\n";
                break;
            }
        }
        catch (const std::exception& greska)
        {
            std::cout << "Greska: " << greska.what() << "\n";
        }
    }
}