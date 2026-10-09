#include <botan/argon2.h>
#include <botan/auto_rng.h>

#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include "PasswordApp.h"

namespace
{
    const std::string DATOTEKA_HASHA = "password_hash.txt";

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

    bool postojiSpremljeniHash()
    {
        std::ifstream datoteka(DATOTEKA_HASHA);
        return datoteka.good() && datoteka.peek() != std::ifstream::traits_type::eof();
    }

    void spremiHash(const std::string& hash)
    {
        std::ofstream datoteka(DATOTEKA_HASHA);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku za spremanje hash vrijednosti.");
        }

        datoteka << hash;
    }

    std::string ucitajHash()
    {
        std::ifstream datoteka(DATOTEKA_HASHA);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti datoteku s hash vrijednosti.");
        }

        std::string hash;
        std::getline(datoteka, hash);

        return hash;
    }

    void generirajHashLozinke()
    {
        std::string lozinka = ucitajTekst("Unesite lozinku koju zelite spremiti: ");

        if (lozinka.empty())
        {
            std::cout << "Lozinka ne smije biti prazna.\n";
            return;
        }

        Botan::AutoSeeded_RNG generatorSlucajnihBrojeva;

        const size_t paralelizam = 1;
        const size_t memorijaKB = 64 * 1024;
        const size_t brojProlaza = 1;
        const size_t varijanta = 2;
        const size_t duljinaSoli = 16;
        const size_t duljinaHasha = 32;

        std::string hash = Botan::argon2_generate_pwhash(
            lozinka.data(),
            lozinka.size(),
            generatorSlucajnihBrojeva,
            paralelizam,
            memorijaKB,
            brojProlaza,
            varijanta,
            duljinaSoli,
            duljinaHasha
        );

        spremiHash(hash);

        std::cout << "\nHash vrijednost je uspjesno generirana i spremljena.\n";
        std::cout << "Spremljeni hash:\n" << hash << "\n";
    }

    void provjeriLozinku()
    {
        if (!postojiSpremljeniHash())
        {
            std::cout << "Ne postoji spremljena hash vrijednost. Prvo generirajte hash lozinke.\n";
            return;
        }

        std::string spremljeniHash = ucitajHash();
        std::string unesenaLozinka = ucitajTekst("Unesite lozinku za provjeru: ");

        bool lozinkaJeIspravna = Botan::argon2_check_pwhash(
            unesenaLozinka.data(),
            unesenaLozinka.size(),
            spremljeniHash
        );

        if (lozinkaJeIspravna)
        {
            std::cout << "Lozinka je ispravna.\n";
        }
        else
        {
            std::cout << "Lozinka nije ispravna.\n";
        }
    }

    void prikaziIzbornikLozinki()
    {
        std::cout << "\n============================================\n";
        std::cout << "  APLIKACIJA ZA SIGURNO SPREMANJE LOZINKI\n";
        std::cout << "============================================\n";
        std::cout << "1. Generiraj i spremi hash lozinke\n";
        std::cout << "2. Provjeri lozinku\n";
        std::cout << "0. Izlaz\n";
        std::cout << "Odabir: ";
    }
}

void PokreniAplikacijuLozinke()
{
    while (true)
    {
        try
        {
            prikaziIzbornikLozinki();
            int odabir = ucitajOdabir();

            switch (odabir)
            {
            case 1:
                generirajHashLozinke();
                break;

            case 2:
                provjeriLozinku();
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