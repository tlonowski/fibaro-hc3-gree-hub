--[[
GREE AC QuickApp Hub — Manual (Lua tab-safe)

PL — Instrukcja (Wersja 2.0 Hub + Urządzenia Potomne)
- Główny QuickApp działa jako Bramka / Hub sieciowy Gree.
- Automatyczne wykrywanie: przy starcie Hub wysyła skan rozgłoszeniowy (UDP 255.255.255.255:7000)
  i odnajduje wszystkie jednostki Gree podłączone do sieci LAN.
- Skanowanie innej sieci / VLANu:
  * scan_network: adres sieci (np. "10.88.20.0/24" lub "10.88.20.0", można podać kilka po przecinku).
  * scan_mask: maska podsieci (np. "255.255.255.0" lub "24", domyślnie "255.255.255.0").
  * Algorytm wysyła directed broadcast oraz omija blokady routera (subnet sweep dla hostów 1..254).
- Każdy wykryty klimatyzator otrzymuje własne urządzenie potomne (Child Device) w HC3.
- Urządzenia potomne mają:
  * Pełny zestaw kontrolek UI: Włącz/Wyłącz, Tryby (Auto, Cool, Dry, Fan, Heat),
    Regulacja temperatury, Wentylator, Ruch żaluzji, Podświetlenie, Cichy, Eco.
  * Kategorię "Klimat / HVAC" w centrali Fibaro HC3.
  * Własne zmienne QuickApp Variables: ac_ip, ac_mac, ac_cid, ac_key, ac_name, refreshSec.
  * Własny, niezależny cykl odpytywania statusu (refreshSec) oraz mechanizm Auto-Reconnect przy zanikach Wi-Fi.
- Ręczne dodanie urządzenia po IP: QuickApp:addAcByIp("192.168.1.X").
- Ręczne skanowanie podsieci: QuickApp:scanSubnet("10.88.20.0/24").
- Kliknięcie przycisku na Hubie wymusza natychmiastowe ponowne przeskanowanie sieci LAN.

EN — Quick notes (Version 2.0 Hub + Child Devices)
- Master QuickApp acts as Gree Network Hub/Gateway.
- Auto-discovery: scans LAN via broadcast UDP 255.255.255.255:7000 on startup.
- Multi-subnet / VLAN scan: via QA variables scan_network (e.g. 10.88.20.0/24) and scan_mask.
- Automatically creates dedicated Child Devices for each discovered AC unit under Climate category.
- Each child device has its own full UI controls, QA variables, and independent Wi-Fi reconnect.
- Manual IP discovery: QuickApp:addAcByIp("192.168.1.X").
]]
