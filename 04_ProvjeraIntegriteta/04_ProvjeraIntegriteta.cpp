#include <botan/hash.h>
#include <botan/hex.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include "IntegrityApp.h"

namespace
{
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

    std::string ukloniRazmake(std::string tekst)
    {
        tekst.erase(
            std::remove_if(tekst.begin(), tekst.end(),
                [](unsigned char znak)
                {
                    return std::isspace(znak);
                }),
            tekst.end());

        return tekst;
    }

    std::string pretvoriUVelikaSlova(std::string tekst)
    {
        std::transform(tekst.begin(), tekst.end(), tekst.begin(),
            [](unsigned char znak)
            {
                return static_cast<char>(std::toupper(znak));
            });

        return tekst;
    }

    std::string normalizirajHash(std::string hash)
    {
        hash = ukloniRazmake(hash);
        hash = pretvoriUVelikaSlova(hash);
        return hash;
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

    std::string izracunajSHA256(const std::string& putanjaDatoteke)
    {
        std::ifstream datoteka(putanjaDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku: " + putanjaDatoteke);
        }

        auto hashFunkcija = Botan::HashFunction::create_or_throw("SHA-256");
        std::array<uint8_t, 4096> spremnik{};

        while (datoteka.good())
        {
            datoteka.read(reinterpret_cast<char*>(spremnik.data()), spremnik.size());
            std::streamsize brojProcitanihBajtova = datoteka.gcount();

            if (brojProcitanihBajtova > 0)
            {
                hashFunkcija->update(spremnik.data(), static_cast<size_t>(brojProcitanihBajtova));
            }
        }

        return Botan::hex_encode(hashFunkcija->final());
    }

    void spremiHashUDatoteku(const std::string& putanjaHashDatoteke, const std::string& hash)
    {
        std::ofstream hashDatoteka(putanjaHashDatoteke);

        if (!hashDatoteka)
        {
            throw std::runtime_error("Nije moguce spremiti hash u datoteku: " + putanjaHashDatoteke);
        }

        hashDatoteka << hash << '\n';
    }

    std::string ucitajHashIzDatoteke(const std::string& putanjaHashDatoteke)
    {
        std::ifstream hashDatoteka(putanjaHashDatoteke);

        if (!hashDatoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku s hash vrijednosti: " + putanjaHashDatoteke);
        }

        std::string hash;
        std::getline(hashDatoteka, hash);

        return hash;
    }

    void izracunajISpremiHash()
    {
        std::string putanjaDatoteke = ocistiPutanju(
            ucitajTekst("Unesite putanju datoteke za koju zelite izracunati hash: ")
        );

        std::string hash = izracunajSHA256(putanjaDatoteke);

        std::cout << "\nIzracunati SHA-256 hash:\n" << hash << "\n";

        std::string putanjaHashDatoteke = ocistiPutanju(
            ucitajTekst("\nUnesite naziv datoteke za spremanje hasha, npr. hash.txt: ")
        );

        spremiHashUDatoteku(putanjaHashDatoteke, hash);

        std::cout << "\nHash je uspjesno spremljen u datoteku: " << putanjaHashDatoteke << "\n";
    }

    void provjeriIntegritetDatoteke()
    {
        std::string putanjaDatoteke = ocistiPutanju(
            ucitajTekst("Unesite putanju datoteke koju zelite provjeriti: ")
        );

        std::string putanjaHashDatoteke = ocistiPutanju(
            ucitajTekst("Unesite putanju datoteke u kojoj je spremljen hash, npr. hash.txt: ")
        );

        std::string spremljeniHash = ucitajHashIzDatoteke(putanjaHashDatoteke);
        std::string trenutniHash = izracunajSHA256(putanjaDatoteke);

        std::cout << "\nSpremljeni hash:\n" << spremljeniHash << "\n";
        std::cout << "\nTrenutni hash:\n" << trenutniHash << "\n";

        if (normalizirajHash(spremljeniHash) == normalizirajHash(trenutniHash))
        {
            std::cout << "\nDatoteka nije mijenjana. Integritet je ocuvan.\n";
        }
        else
        {
            std::cout << "\nDatoteka je promijenjena. Integritet nije ocuvan.\n";
        }
    }

    void prikaziIzbornikIntegriteta()
    {
        std::cout << "\n============================================\n";
        std::cout << "  APLIKACIJA ZA PROVJERU INTEGRITETA\n";
        std::cout << "============================================\n";
        std::cout << "1. Izracunaj i spremi SHA-256 hash datoteke\n";
        std::cout << "2. Provjeri integritet datoteke\n";
        std::cout << "0. Izlaz\n";
        std::cout << "Odabir: ";
    }
}

void PokreniAplikacijuIntegriteta()
{
    while (true)
    {
        try
        {
            prikaziIzbornikIntegriteta();
            int odabir = ucitajOdabir();

            switch (odabir)
            {
            case 1:
                izracunajISpremiHash();
                break;

            case 2:
                provjeriIntegritetDatoteke();
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