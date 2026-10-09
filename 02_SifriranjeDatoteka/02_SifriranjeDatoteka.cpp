#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <botan/secmem.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "EncryptionApp.h"

namespace
{
    constexpr size_t DULJINA_KLJUCA = 32;
    constexpr size_t DULJINA_SOLI = 16;
    constexpr size_t DULJINA_JEDNOKRATNE_VRIJEDNOSTI = 12;
    constexpr size_t BROJ_PBKDF2_ITERACIJA = 200000;

    const std::array<uint8_t, 4> OZNAKA_FORMATA = { 'B', 'T', 'N', '2' };

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

    Botan::secure_vector<uint8_t> izvediKljuc(
        std::string_view lozinka,
        std::span<const uint8_t> sol)
    {
        auto obiteljHashaLozinke =
            Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");

        auto hashLozinke = obiteljHashaLozinke->from_params(BROJ_PBKDF2_ITERACIJA);

        Botan::secure_vector<uint8_t> kljuc(DULJINA_KLJUCA);

        hashLozinke->hash(
            std::span<uint8_t>(kljuc.data(), kljuc.size()),
            lozinka,
            sol
        );

        return kljuc;
    }

    std::vector<uint8_t> napraviPaket(
        std::span<const uint8_t> sol,
        std::span<const uint8_t> jednokratnaVrijednost,
        std::span<const uint8_t> sifriraniSadrzaj)
    {
        std::vector<uint8_t> paket;

        paket.insert(paket.end(), OZNAKA_FORMATA.begin(), OZNAKA_FORMATA.end());
        paket.insert(paket.end(), sol.begin(), sol.end());
        paket.insert(paket.end(), jednokratnaVrijednost.begin(), jednokratnaVrijednost.end());
        paket.insert(paket.end(), sifriraniSadrzaj.begin(), sifriraniSadrzaj.end());

        return paket;
    }

    std::vector<uint8_t> sifrirajPodatke(
        std::string_view lozinka,
        std::span<const uint8_t> izvorniPodaci,
        Botan::RandomNumberGenerator& generatorSlucajnihBrojeva)
    {
        const auto sol = generatorSlucajnihBrojeva.random_array<DULJINA_SOLI>();
        const auto jednokratnaVrijednost = generatorSlucajnihBrojeva.random_array<DULJINA_JEDNOKRATNE_VRIJEDNOSTI>();

        auto kljuc = izvediKljuc(lozinka, sol);

        auto sifra = Botan::AEAD_Mode::create_or_throw(
            "AES-256/GCM",
            Botan::Cipher_Dir::Encryption
        );

        sifra->set_key(std::span<const uint8_t>(kljuc.data(), kljuc.size()));
        sifra->start(jednokratnaVrijednost);

        Botan::secure_vector<uint8_t> spremnik(izvorniPodaci.begin(), izvorniPodaci.end());

        sifra->finish(spremnik);

        return napraviPaket(sol, jednokratnaVrijednost, spremnik);
    }

    Botan::secure_vector<uint8_t> desifrirajPodatke(
        std::string_view lozinka,
        std::span<const uint8_t> sifriraniPaket)
    {
        const size_t duljinaZaglavlja = OZNAKA_FORMATA.size() + DULJINA_SOLI + DULJINA_JEDNOKRATNE_VRIJEDNOSTI;

        if (sifriraniPaket.size() <= duljinaZaglavlja)
        {
            throw std::runtime_error("Sifrirani podatak je prekratak ili nije ispravan.");
        }

        for (size_t indeks = 0; indeks < OZNAKA_FORMATA.size(); indeks++)
        {
            if (sifriraniPaket[indeks] != OZNAKA_FORMATA[indeks])
            {
                throw std::runtime_error("Datoteka ili tekst nisu u ispravnom formatu.");
            }
        }

        auto sol = sifriraniPaket.subspan(OZNAKA_FORMATA.size(), DULJINA_SOLI);
        auto jednokratnaVrijednost = sifriraniPaket.subspan(OZNAKA_FORMATA.size() + DULJINA_SOLI, DULJINA_JEDNOKRATNE_VRIJEDNOSTI);
        auto sifriraniSadrzaj = sifriraniPaket.subspan(OZNAKA_FORMATA.size() + DULJINA_SOLI + DULJINA_JEDNOKRATNE_VRIJEDNOSTI);

        auto kljuc = izvediKljuc(lozinka, sol);

        auto sifra = Botan::AEAD_Mode::create_or_throw(
            "AES-256/GCM",
            Botan::Cipher_Dir::Decryption
        );

        sifra->set_key(std::span<const uint8_t>(kljuc.data(), kljuc.size()));
        sifra->start(jednokratnaVrijednost);

        Botan::secure_vector<uint8_t> spremnik(sifriraniSadrzaj.begin(), sifriraniSadrzaj.end());

        try
        {
            sifra->finish(spremnik);
        }
        catch (const Botan::Invalid_Authentication_Tag&)
        {
            throw std::runtime_error("Desifriranje nije uspjelo. Lozinka je pogresna ili su podaci izmijenjeni.");
        }

        return spremnik;
    }

    std::vector<uint8_t> pretvoriTekstUBajtove(const std::string& tekst)
    {
        return std::vector<uint8_t>(tekst.begin(), tekst.end());
    }

    std::string pretvoriBajtoveUTekst(std::span<const uint8_t> bajtovi)
    {
        return std::string(bajtovi.begin(), bajtovi.end());
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

    std::vector<uint8_t> ucitajDatoteku(const std::string& putanjaDatoteke)
    {
        std::ifstream datoteka(putanjaDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti ulaznu datoteku: " + putanjaDatoteke);
        }

        return std::vector<uint8_t>(
            std::istreambuf_iterator<char>(datoteka),
            std::istreambuf_iterator<char>()
        );
    }

    void spremiDatoteku(const std::string& putanjaDatoteke, std::span<const uint8_t> podaci)
    {
        std::ofstream datoteka(putanjaDatoteke, std::ios::binary);

        if (!datoteka)
        {
            throw std::runtime_error("Nije moguce otvoriti izlaznu datoteku: " + putanjaDatoteke);
        }

        datoteka.write(reinterpret_cast<const char*>(podaci.data()), podaci.size());
    }

    void sifrirajTekst(Botan::RandomNumberGenerator& generatorSlucajnihBrojeva)
    {
        std::string tekst = ucitajTekst("Unesite tekst za sifriranje: ");
        std::string lozinka = ucitajTekst("Unesite tajnu lozinku/kljuc: ");

        auto izvorniPodaci = pretvoriTekstUBajtove(tekst);
        auto sifriraniPodaci = sifrirajPodatke(lozinka, izvorniPodaci, generatorSlucajnihBrojeva);

        std::cout << "\nSifrirani tekst HEX:\n";
        std::cout << Botan::hex_encode(sifriraniPodaci) << "\n";
    }

    void desifrirajTekst()
    {
        std::string sifriraniTekstHex = ucitajTekst("Unesite sifrirani tekst HEX: ");
        std::string lozinka = ucitajTekst("Unesite tajnu lozinku/kljuc: ");

        auto sifriraniPodaci = Botan::hex_decode(sifriraniTekstHex);

        auto desifriraniPodaci = desifrirajPodatke(
            lozinka,
            std::span<const uint8_t>(sifriraniPodaci.data(), sifriraniPodaci.size())
        );

        std::cout << "\nDesifrirani tekst:\n";
        std::cout << pretvoriBajtoveUTekst(desifriraniPodaci) << "\n";
    }

    void sifrirajDatoteku(Botan::RandomNumberGenerator& generatorSlucajnihBrojeva)
    {
        std::string ulaznaPutanja = ocistiPutanju(ucitajTekst("Putanja do datoteke za sifriranje: "));
        std::string izlaznaPutanja = ocistiPutanju(ucitajTekst("Putanja za spremanje sifrirane datoteke: "));
        std::string lozinka = ucitajTekst("Unesite tajnu lozinku/kljuc: ");

        auto podaciDatoteke = ucitajDatoteku(ulaznaPutanja);

        auto sifriraniPodaci = sifrirajPodatke(
            lozinka,
            std::span<const uint8_t>(podaciDatoteke.data(), podaciDatoteke.size()),
            generatorSlucajnihBrojeva
        );

        spremiDatoteku(izlaznaPutanja, sifriraniPodaci);

        std::cout << "Datoteka je uspjesno sifrirana.\n";
    }

    void desifrirajDatoteku()
    {
        std::string ulaznaPutanja = ocistiPutanju(ucitajTekst("Putanja do sifrirane datoteke: "));
        std::string izlaznaPutanja = ocistiPutanju(ucitajTekst("Putanja za spremanje desifrirane datoteke: "));
        std::string lozinka = ucitajTekst("Unesite tajnu lozinku/kljuc: ");

        auto sifriraniPodaciDatoteke = ucitajDatoteku(ulaznaPutanja);

        auto desifriraniPodaci = desifrirajPodatke(
            lozinka,
            std::span<const uint8_t>(sifriraniPodaciDatoteke.data(), sifriraniPodaciDatoteke.size())
        );

        spremiDatoteku(izlaznaPutanja, desifriraniPodaci);

        std::cout << "Datoteka je uspjesno desifrirana.\n";
    }

    void prikaziIzbornikSifriranja()
    {
        std::cout << "\n============================================\n";
        std::cout << "  APLIKACIJA ZA SIFRIRANJE I DESIFRIRANJE\n";
        std::cout << "============================================\n";
        std::cout << "1. Sifriraj tekst\n";
        std::cout << "2. Desifriraj tekst\n";
        std::cout << "3. Sifriraj datoteku\n";
        std::cout << "4. Desifriraj datoteku\n";
        std::cout << "0. Izlaz\n";
        std::cout << "Odabir: ";
    }
}

void PokreniAplikacijuSifriranja()
{
    Botan::AutoSeeded_RNG generatorSlucajnihBrojeva;

    while (true)
    {
        try
        {
            prikaziIzbornikSifriranja();
            int odabir = ucitajOdabir();

            switch (odabir)
            {
            case 1:
                sifrirajTekst(generatorSlucajnihBrojeva);
                break;

            case 2:
                desifrirajTekst();
                break;

            case 3:
                sifrirajDatoteku(generatorSlucajnihBrojeva);
                break;

            case 4:
                desifrirajDatoteku();
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