#include <iostream>
#include <limits>

#include "../01_SpremanjeLozinki/PasswordApp.h"
#include "../02_SifriranjeDatoteka/EncryptionApp.h"
#include "../03_DigitalniPotpis/SignatureApp.h"
#include "../04_ProvjeraIntegriteta/IntegrityApp.h"

void ocistiUnos()
{
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main()
{
    int odabir;

    do
    {
        std::cout << "\n============================================\n";
        std::cout << "  KRIPTOGRAFSKE APLIKACIJE U BOTANU\n";
        std::cout << "============================================\n";
        std::cout << "1. Sigurno spremanje lozinki\n";
        std::cout << "2. Kriptiranje i dekriptiranje podataka\n";
        std::cout << "3. Digitalni potpis\n";
        std::cout << "4. Provjera integriteta datoteke\n";
        std::cout << "0. Izlaz\n";
        std::cout << "--------------------------------------------\n";
        std::cout << "Odabir: ";

        std::cin >> odabir;

        if (std::cin.fail())
        {
            ocistiUnos();
            std::cout << "Neispravan unos. Pokusajte ponovno.\n";
            continue;
        }

        ocistiUnos();

        switch (odabir)
        {
        case 1:
            PokreniAplikacijuLozinke();
            break;

        case 2:
            PokreniAplikacijuSifriranja();
            break;

        case 3:
            PokreniAplikacijuDigitalnogPotpisa();
            break;

        case 4:
            PokreniAplikacijuIntegriteta();
            break;

        case 0:
            std::cout << "Izlaz iz programa.\n";
            break;

        default:
            std::cout << "Nepostojeca opcija. Pokusajte ponovno.\n";
            break;
        }

    } while (odabir != 0);

    return 0;
}