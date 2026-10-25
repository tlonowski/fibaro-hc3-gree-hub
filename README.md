# Gree AC QuickApp Hub / Gateway (Fibaro Home Center 3)

**Wersja / Version:** 2.0  
**Autor / Author:** Tomasz Lonowski (@tlonowski)

[🇵🇱 Wersja polska](#-wersja-polska) | [🇬🇧 English version](#-english-version)

---

## 🇵🇱 Wersja polska

### Opis projektu

**Gree AC QuickApp Hub** to zaawansowana integracja klimatyzatorów marki **Gree** (oraz jednostek kompatybilnych z protokołem Gree Wi-Fi) z centralą **Fibaro Home Center 3 (HC3)**.

Projekt w wersji 2.0 wykorzystuje architekturę **Hub + Urządzenia Potomne (Child Devices)**:
- **Jeden główny QuickApp (Hub / Bramka)** zarządza pojedynczym gniazdem sieciowym UDP na porcie `7000`, eliminując konflikty portów w centrali HC3 oraz problemy z osieroconymi gniazdami.
- **Automatyczne wykrywanie (Auto-Discovery)** w sieci LAN oraz przez podsieci / VLAN-y (obsługa broadcastu oraz *subnet sweep* omijającego blokady rozgłoszeniowe na routerach).
- **Dedykowane urządzenia potomne** dla każdego wykrytego klimatyzatora z kategorią *Klimat / HVAC* (`AirConditioner`), pełnym panelem sterowania UI oraz obsługą w scenach i aplikacji mobilnej **Yubii**.

### Główne możliwości

- 🔍 **Automatyczne skanowanie sieci LAN i VLAN**: Wykrywanie jednostek Gree przez broadcast (`255.255.255.255:7000`) oraz aktywne skanowanie adresów IP we wskazanych podsieciach (np. osobny VLAN IoT).
- 🔐 **Automatyczne parowanie (Binding)**: Pobieranie i zapisywanie indywidualnego klucza szyfrowania AES (`ac_key`) dla każdej jednostki.
- 📱 **Pełny panel sterowania dla każdego klimatyzatora**:
  - Włączanie / Wyłączanie (`Pow`) + globalny wyłącznik/włącznik wszystkich jednostek z poziomu Huba
  - Zmiana trybu pracy (`Mod`): **Auto** 🤖, **Chłodzenie (Cool)** ❄️, **Osuszanie (Dry)** 🌀, **Wentylator (Fan)** ✇, **Grzanie (Heat)** 🔥
  - Regulacja temperatury zadanej (`SetTem`): zakres `16°C – 30°C`
  - Sterowanie prędkością wentylatora (`WdSpd`): Auto, Niski, Średnio niski, Średnio wysoki, Wysoki
  - Ustawienia ruchu żaluzji pionowych (`SwUpDn`): Domyślne, Pełny ruch, Pozycja środkowa
  - Funkcje dodatkowe: **Podświetlenie wyświetlacza** (`Lig` 💡), **Tryb cichy** (`Quiet` 🌙), **Oszczędzanie energii / Eco** (`SvSt` 🌿)
- 🔄 **Niezależny odczyt statusu i Auto-Reconnect**: Kolejkowanie zapytań UDP w Hubie, cykliczny odczyt parametrów każdej jednostki oraz automatyczne wznawianie połączenia przy zanikach sygnału Wi-Fi.
- 🌍 **Wielojęzyczność**: Tłumaczenia interfejsu i statusów dla języków: polski (`pl`), angielski (`en`), niemiecki (`de`), francuski (`fr`).

### Struktura plików QuickApp

| Plik | Opis |
| :--- | :--- |
| [`main.lua`](main.lua) | Główna logika Huba, obsługa gniazda UDP (port 7000), kolejkowanie pakietów, skanowanie podsieci, parowanie oraz obsługa urządzeń potomnych (`QuickAppChild`). |
| [`aeslib.lua`](aeslib.lua) | Biblioteka czystego Lua realizująca szyfrowanie/deszyfrowanie **AES-128-ECB** oraz dopełnianie **PKCS#7** wymagane przez protokół Gree. |
| [`base64.lua`](base64.lua) | Kodowanie i dekodowanie formatu Base64 dla pakietów komunikacyjnych JSON/UDP. |
| [`translations.lua`](translations.lua) | Słownik tłumaczeń etykiet i komunikatów UI (`pl`, `en`, `de`, `fr`). |
| [`manual.lua`](manual.lua) | Wbudowana ściąga i dokumentacja parametrów dostępna bezpośrednio w zakładkach edycji QuickApp w HC3. |
| [`udplib.lua`](udplib.lua) | Plik pomocniczy zachowany dla kompatybilności struktury QA (samo gniazdo UDP jest zarządzane centralnie w `main.lua`). |

### Instalacja w Fibaro HC3

1. W panelu **Fibaro Home Center 3** przejdź do **Ustawienia -> Urządzenia -> Dodaj urządzenie -> Inne urządzenie -> QuickApp**.
2. Wybierz typ urządzenia (np. *Urządzenie binarne* lub *Kontroler klimatyzacji*) i utwórz pusty QuickApp.
3. W zakładce **Edycja i pliki** utwórz/podmień pliki zgodnie z zawartością tego repozytorium:
   - Wklej zawartość [`main.lua`](main.lua) do głównego pliku `main`.
   - Dodaj pozostałe pliki modułów: [`aeslib.lua`](aeslib.lua), [`base64.lua`](base64.lua), [`translations.lua`](translations.lua), [`manual.lua`](manual.lua), [`udplib.lua`](udplib.lua).
4. Zapisz projekt. Hub automatycznie utworzy domyślne zmienne i rozpocznie skanowanie sieci LAN w poszukiwaniu klimatyzatorów Gree.

### Konfiguracja (QuickApp Variables)

#### Zmienne głównego Huba:
- `scan_network` – adres podsieci do skanowania (np. `10.88.20.0/24` lub kilka podsieci po przecinku). Przydatne, gdy klimatyzatory znajdują się w innym VLAN-ie niż centrala HC3.
- `scan_mask` – maska podsieci (domyślnie `255.255.255.0`).
- `ac_names` – opcjonalne mapowanie własnych nazw jednostek po ID/MAC/IP (np. `1ef92c54=Salon, 1ef92afc=Sypialnia, 1ee2f5e9=Gabinet`).
- `refreshSec` – domyślny czas odświeżania statusu w sekundach (domyślnie `120`).
- `showDebug` – włączenie szczegółowych logów w konsoli HC3 (`true` / `false`).

#### Zmienne każdego urządzenia potomnego (tworzone automatycznie):
- `ac_ip` – adres IP klimatyzatora
- `ac_mac` – adres fizyczny MAC jednostki
- `ac_cid` – identyfikator CID urządzenia
- `ac_key` – wynegocjowany klucz AES urządzenia
- `ac_name` – nazwa jednostki
- `refreshSec` – interwał odpytywania danej jednostki w sekundach

#### Przydatne wywołania ze scen Lua:
- Ręczne dodanie klimatyzatora po adresie IP:
  ```lua
  fibaro.call(HUB_ID, "addAcByIp", "192.168.1.50")
  ```
- Ręczne wymuszenie skanowania wybranej podsieci:
  ```lua
  fibaro.call(HUB_ID, "scanSubnet", "10.88.20.0/24")
  ```
- Sterowanie pojedynczym klimatyzatorem (urządzeniem potomnym):
  ```lua
  fibaro.call(CHILD_ID, "turnOn")
  fibaro.call(CHILD_ID, "setThermostatMode", "cool")
  fibaro.call(CHILD_ID, "setTargetTemperature", 22)
  fibaro.call(CHILD_ID, "turnOff")
  ```

---

## 🇬🇧 English Version

### Overview

**Gree AC QuickApp Hub** is a complete integration for **Gree** air conditioners (and Gree Wi-Fi protocol compatible HVAC units) designed for **Fibaro Home Center 3 (HC3)**.

Version 2.0 introduces a **Hub + Child Devices architecture**:
- **Single Master QuickApp (Hub / Gateway)** manages a single central UDP socket on port `7000`, preventing port collisions and orphan socket issues on HC3.
- **Automatic Discovery** across local LAN and custom subnets / VLANs (supports both broadcast and active *subnet sweep* for routers blocking directed broadcasts).
- **Dedicated Child Devices** automatically generated for each discovered AC unit under the *Climate / HVAC* (`AirConditioner`) category, complete with rich UI controls and support for HC3 scenes and the **Yubii** mobile app.

### Key Features

- 🔍 **Auto-Discovery (LAN & Multi-VLAN)**: Scans via UDP broadcast (`255.255.255.255:7000`) and performs unicast subnet sweeps (`1..254`) for configured IoT VLANs.
- 🔐 **Automatic Pairing (Binding)**: Negotiates and stores the per-device AES encryption key (`ac_key`) automatically.
- 📱 **Full UI Control Panel per AC Unit**:
  - Power ON / OFF (`Pow`) + Master ON/OFF buttons on the Hub
  - Operating Modes (`Mod`): **Auto** 🤖, **Cool** ❄️, **Dry** 🌀, **Fan** ✇, **Heat** 🔥
  - Target Temperature (`SetTem`): `16°C – 30°C`
  - Fan Speed (`WdSpd`): Auto, Low, Medium-Low, Medium-High, High
  - Vertical Swing (`SwUpDn`): Default, Full Swing, Fixed Middle
  - Extra Features: **Display Light** (`Lig` 💡), **Quiet Mode** (`Quiet` 🌙), **Energy Saving / Eco** (`SvSt` 🌿)
- 🔄 **Central UDP Queue & Auto-Reconnect**: Serialized UDP communication prevents packet drops, while periodic polling and automatic Wi-Fi reconnect keep statuses synchronized.
- 🌍 **Multi-language Support**: Built-in translations for Polish (`pl`), English (`en`), German (`de`), and French (`fr`).

### QuickApp File Structure

| File | Description |
| :--- | :--- |
| [`main.lua`](main.lua) | Core Hub logic, central UDP socket management (port 7000), request queue, subnet scanner, device binding, and `QuickAppChild` management. |
| [`aeslib.lua`](aeslib.lua) | Pure Lua **AES-128-ECB** encryption/decryption and **PKCS#7** padding library required by the Gree protocol. |
| [`base64.lua`](base64.lua) | Base64 encoder/decoder for JSON/UDP payloads. |
| [`translations.lua`](translations.lua) | UI and status translation dictionaries (`pl`, `en`, `de`, `fr`). |
| [`manual.lua`](manual.lua) | Quick reference manual accessible inside the HC3 QuickApp editor. |
| [`udplib.lua`](udplib.lua) | Compatibility stub (UDP socket is centrally managed inside `main.lua`). |

### Configuration (QuickApp Variables)

- `scan_network` – subnet(s) to scan, e.g., `10.88.20.0/24` (comma-separated if multiple).
- `scan_mask` – subnet mask (default `255.255.255.0`).
- `ac_names` – custom name mapping by CID/MAC/IP (e.g., `1ef92c54=LivingRoom, 1ef92afc=Bedroom`).
- `refreshSec` – status polling interval in seconds (default `120`).
- `showDebug` – enable verbose logging in HC3 console (`true` / `false`).
