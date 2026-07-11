

# Dokumentacja techniczna systemu NetPulse

**Sieciowy system wykrywania intruzów (Network Intrusion Detection System)**
*Dokumentacja architektury i modułów*

## Przygotowana przez:
- Mateusz Mariasik 251185
- Kacper Łukaszewski 251181
---

## Spis treści

1. [Wprowadzenie](#1-wprowadzenie)
2. [Architektura systemu](#2-architektura-systemu)
3. [Wymagania systemowe i zależności](#3-wymagania-systemowe-i-zależności)
4. [Struktura katalogów repozytorium](#4-struktura-katalogów-repozytorium)
5. [Szczegółowy opis modułów](#5-szczegółowy-opis-modułów)
6. [Model danych](#6-model-danych)
7. [Interfejs API (REST + SSE)](#7-interfejs-api-rest--sse)
8. [Bezpieczeństwo systemu](#8-bezpieczeństwo-systemu)
9. [Instalacja i uruchomienie](#9-instalacja-i-uruchomienie)
10. [Znane ograniczenia i rekomendowane kierunki rozwoju](#10-znane-ograniczenia-i-rekomendowane-kierunki-rozwoju)
11. [Podsumowanie](#11-podsumowanie)

---

## 1. Wprowadzenie

### 1.1 Cel dokumentu

Niniejszy dokument stanowi kompletną dokumentację techniczną projektu **NetPulse** — systemu klasy IDS (Intrusion Detection System), przeznaczonego do pasywnego monitorowania ruchu sieciowego, wykrywania anomalii oraz nadzoru nad kondycją urządzeń sieciowych w czasie rzeczywistym. Dokumentacja opisuje faktyczny stan implementacji — architekturę, poszczególne moduły, przepływ danych, model bazy danych, interfejs API oraz warstwę prezentacji.

### 1.2 Czym jest NetPulse

NetPulse jest projektem w pełni open source, zaprojektowanym z myślą o uniwersalności — może być wdrożony w dowolnej infrastrukturze sieciowej i współpracować z urządzeniami różnych producentów (Cisco, Linux/Unix, MikroTik, Windows Server, Huawei, Juniper), pod warunkiem obsługi protokołu SNMP.

Koncepcyjnie system nawiązuje do rozwiązań klasy enterprise, takich jak Arbor Networks (systemy anty-DDoS i detekcji anomalii wolumetrycznych) oraz Zabbix (monitoring infrastruktury sieciowej z wykorzystaniem SNMP), łącząc obie te filozofie w jednym, spójnym, samodzielnie hostowanym narzędziu:

- z **Arbor Networks** NetPulse zapożycza ideę detekcji anomalii ruchu w oparciu o analizę statystyczną (średnie kroczące, proporcje pakietów, wolumetria) w celu wykrywania ataków DDoS/DoS,
- z **Zabbixa** — podejście do monitoringu urządzeń poprzez SNMP (odpytywanie liczników interfejsów, zużycia CPU/RAM, wykrywanie awarii łączy) oraz ideę centralnego dashboardu prezentującego stan floty urządzeń.

W odróżnieniu od komercyjnych odpowiedników, NetPulse jest rozwiązaniem w pełni jawnym i dostępnym publicznie — kod źródłowy, reguły detekcji oraz cała logika analityczna mogą być swobodnie przeglądane, audytowane i modyfikowane przez każdego, co ma znaczenie zarówno edukacyjne, jak i praktyczne (możliwość dostosowania progów detekcji do specyfiki własnej sieci).

### 1.3 Charakter systemu — hybrydowy IDS

NetPulse łączy w sobie dwa niezależne, uzupełniające się mechanizmy detekcji zagrożeń:

1. **Detekcja oparta na przechwytywaniu pakietów** (packet-based IDS) — realizowana poprzez pasywne nasłuchiwanie na porcie mirroringu (SPAN/port mirroring) za pomocą biblioteki Scapy. Ruch jest analizowany "na żywo", pakiet po pakiecie, w poszukiwaniu sygnatur ataków sieciowych (skanowanie portów, ARP spoofing, tunelowanie ICMP, floody wolumetryczne).
2. **Detekcja oparta na telemetrii SNMP** (SNMP-based monitoring/IDS) — realizowana poprzez cykliczne odpytywanie zarządzanych urządzeń o liczniki systemowe (CPU, RAM, liczniki interfejsów) i wykrywanie w nich anomalii wskazujących na ataki wyższego poziomu (wyczerpanie zasobów, wycieki pamięci, eksfiltrację danych, niestabilność łączy).

Obie ścieżki detekcji zasilają wspólną magistralę zdarzeń (event bus), z której alerty trafiają jednocześnie do: bazy danych (trwały log), interfejsu webowego (powiadomienia w czasie rzeczywistym poprzez Server-Sent Events) oraz bota Telegram (powiadomienia push do administratorów).

---

## 2. Architektura systemu

### 2.1 Widok ogólny

System NetPulse zbudowany jest w architekturze modułowej, w której można wyróżnić pięć głównych warstw:

| Warstwa | Odpowiedzialność | Kluczowe moduły |
|---|---|---|
| Warstwa akwizycji danych | Przechwytywanie ruchu sieciowego oraz odpytywanie urządzeń | `workers/MySnifferClass.py`, `workers/SubnetScanner.py`, `workers/SnmpPoller.py` |
| Warstwa analizy / detekcji | Wykrywanie anomalii i ataków na podstawie zebranych danych | `workers/PacketAnalyzer.py`, `workers/SnmpAnalyzer.py` |
| Warstwa orkiestracji | Koordynacja cyklu skanowania sieci i odpytywania urządzeń | `workers/main.py`, `workers/PollerManager.py` |
| Warstwa danych i zdarzeń | Persystencja danych oraz dystrybucja zdarzeń w systemie | `db_tools/db_tools.py`, `core/event_bus.py` |
| Warstwa prezentacji / API | REST API, uwierzytelnianie, dashboard webowy, powiadomienia | `app.py`, `routes/*`, `services/*`, `serializers/*`, `static/*`, `helpers/notification_manager.py` |

### 2.2 Diagram przepływu danych (opis)

Logiczny przepływ danych w systemie przebiega następująco:

1. **Odkrywanie urządzeń** — moduł `SubnetScanner` wykonuje cykliczne skanowanie ARP wszystkich podsieci podpiętych do interfejsu monitorującego, tworząc listę żywych hostów (adres IP + adres MAC).
2. **Identyfikacja urządzeń (Discovery)** — dla każdego nowo odnalezionego hosta `AsyncSNMPPoller` (moduł `SnmpPoller.py`) wykonuje zapytanie SNMP o podstawowe OID-y systemowe (`sysDescr`, `sysName`, `sysServices`, `ifNumber`), próbując kolejno domyślnych społeczności SNMP. Na tej podstawie ustalany jest producent urządzenia (vendor) oraz — przy pomocy słownika `devices.json` i modułu `PollerManager` — jego typ (Router / Switch / inne).
3. **Cykliczne odpytywanie telemetrii** — `PollerManager.poll_metrics()` w regularnych odstępach czasu odpytuje wszystkie zarejestrowane urządzenia o metryki wydajnościowe (CPU, RAM, w zależności od rodziny urządzenia) oraz statystyki poszczególnych interfejsów sieciowych (liczniki bajtów, pakietów, błędów).
4. **Równoległa analiza pakietów na żywo** — niezależnie od pollingu SNMP, proces nasłuchujący (`MySniffer`) w czasie rzeczywistym przechwytuje każdy pakiet widoczny na porcie mirroringu i przekazuje jego cechy do kolejki międzyprocesowej.
5. **Detekcja anomalii** — dwa niezależne silniki analityczne (`MyAnalyzer` dla pakietów, `SNMPTelemetryAnalyzer` dla telemetrii) analizują strumienie danych w poszukiwaniu wzorców ataków.
6. **Emisja zdarzeń** — każde wykryte zagrożenie generuje zdarzenie (event), które jest przekazywane do `core/event_bus.py`.
7. **Dystrybucja alertu** — magistrala zdarzeń jednocześnie: a) zapisuje log do kolekcji `logs` w MongoDB, b) przesyła zdarzenie do wszystkich aktywnie podłączonych klientów przeglądarkowych poprzez strumień SSE (`/events`), c) umieszcza zdarzenie w kolejce powiadomień Telegram, d) automatycznie emituje dodatkowy sygnał odświeżenia danych `DATA_REFRESH_SIGNAL` do wszystkich podłączonych klientów.
8. **Prezentacja** — panel webowy (`static/dashboard.html`) pobiera dane historyczne poprzez REST API (`/devices`, `/metrics`, `/logs`) oraz nasłuchuje zdarzeń na żywo poprzez SSE, renderując wykresy, listę urządzeń oraz listę alertów.

### 2.3 Model procesów i współbieżności

NetPulse wykorzystuje kilka modeli współbieżności jednocześnie, dobranych do charakteru poszczególnych zadań:

- **Wątek (thread)** — główna pętla robocza (`workers.main.main`) uruchamiana jest jako osobny wątek (`threading.Thread`, `daemon=True`) względem procesu serwera Flask, tak aby serwer HTTP i logika monitoringu działały równolegle w ramach jednego procesu Pythona.
- **Sniffing w tle** — przechwytywanie pakietów odbywa się poprzez `AsyncSniffer` z biblioteki Scapy, który wewnętrznie zarządza własnym wątkiem nasłuchującym na interfejsie sieciowym, wywołując funkcję zwrotną (`detailed_callback`) dla każdego przechwyconego pakietu.
- **Kolejka międzyprocesowa** (`multiprocessing.Queue`) — służy jako bufor pomiędzy sniffem pakietów a analizatorem asynchronicznym, co odseparowuje operację przechwytywania (I/O-bound, zależną od sterownika karty sieciowej) od operacji analitycznej.
- **Pętla zdarzeń asyncio** — cała logika odpytywania SNMP oraz analizy telemetrii/pakietów zbudowana jest w oparciu o `asyncio`, co pozwala na współbieżne odpytywanie wielu urządzeń i wielu portów jednocześnie bez blokowania pętli zdarzeń (`asyncio.gather`).
- **Wątki pomocnicze** — moduł powiadomień Telegram uruchamia dwa dodatkowe wątki demonowe: jeden do odpytywania (long polling) API Telegrama o nowe wiadomości, drugi do wysyłki powiadomień z kolejki.

---

## 3. Wymagania systemowe i zależności

### 3.1 Wymagania środowiskowe

Do poprawnego działania NetPulse wymagane jest:

- **System operacyjny z rodziny Linux** — ze względu na wykorzystanie `AsyncSniffer` w trybie surowego przechwytywania ramek oraz odczyt interfejsów sieciowych poprzez `scapy`/`netifaces`.
- **Uprawnienia administratora (root / sudo)** — niezbędne do otwarcia gniazda surowego (raw socket) wymaganego przez sniffer pakietów oraz do wysyłania zapytań ARP.
- **Jeden lub dwa interfejsy sieciowe** — Liczba wymaganych interfejsów zależy od obsługi funkcji Port Mirroring przez przełącznik sieciowy (tj. tego, czy przełącznik blokuje standardową komunikację na porcie lustrzanym). Aplikacja wymaga odrębnego zdefiniowania interfejsu komunikacyjnego oraz interfejsu monitorującego (nasłuchującego). Jeśli dany interfejs jest w stanie realizować obie te funkcje jednocześnie, w konfiguracji należy wskazać go dwukrotnie.
- **Serwer bazy danych MongoDB** działający lokalnie na standardowym porcie 27017 (domyślnie `mongodb://localhost:27017/NetPulse`, konfigurowalne przez zmienną środowiskową `MONGO_URI`).
- **Certyfikaty TLS** — aplikacja uruchamia wbudowany serwer Flask z obsługą HTTPS, korzystając z pary klucz/certyfikat znajdującej się w katalogu `certs/` (`cert.pem`, `key.pem`); w repozytorium znajduje się certyfikat deweloperski (samopodpisany) — jego status ważności omówiono w rozdziale.
- **Skonfigurowane zmienne środowiskowe** — aplikacja odczytuje sekrety i parametry połączeń z pliku `.env`, na bazie dołączonego do repozytorium szablonu `.env.example`; szczegóły w rozdziale.

### 3.2 Zależności — biblioteki Python

Repozytorium zawiera plik **`requirements.txt`** z przypiętymi wersjami zależności:

```
aiofiles==25.1.0
click==8.4.2
Flask==3.1.3
flask_cors==6.0.2
flask_pymongo==3.0.1
netaddr==1.3.0
netifaces==0.11.0
pymongo==4.17.0
pysnmp==7.1.27
python-dotenv==1.2.2
Requests==2.34.2
scapy==2.7.0
```

| Biblioteka | Zastosowanie w projekcie |
|---|---|
| Flask | Serwer WWW / REST API, routing, sesje, obsługa żądań |
| flask_cors | Obsługa nagłówków CORS dla komunikacji z frontendem |
| flask_pymongo | Integracja Flask z MongoDB (`app.mongo`) |
| pymongo | Bezpośredni klient MongoDB używany w `db_tools.py` |
| scapy | Przechwytywanie pakietów (sniffing), konstruowanie i wysyłanie ramek ARP (skanowanie sieci) |
| pysnmp (`hlapi.asyncio`) | Asynchroniczna komunikacja SNMP z urządzeniami sieciowymi |
| netifaces | Odczyt adresów IP/masek przypisanych do interfejsów sieciowych |
| netaddr | Operacje na adresach/sieciach CIDR podczas skanowania podsieci |
| aiofiles | Asynchroniczny odczyt pliku `devices.json` (mapowanie typów urządzeń) |
| requests | Komunikacja HTTP z API Telegram Bot |
| click | Zależność Flask (CLI), tłumiona w kodzie startowym aplikacji |
| python-dotenv | Wczytywanie zmiennych środowiskowych z pliku konfiguracyjnego na potrzeby `config.py` |

Dodatkowo wykorzystywane są wyłącznie moduły standardowej biblioteki Pythona: `asyncio`, `threading`, `multiprocessing`, `queue`, `collections` (`defaultdict`, `deque`, `Counter`), `ipaddress`, `datetime`, `zoneinfo`, `json`, `os`, `socket`, `math`, `time`, `logging`, `pprint`.

### 3.3 Baza danych

Projekt wykorzystuje MongoDB jako jedyny magazyn danych trwałych. Baza nosi nazwę `NetPulse` i zawiera następujące kolekcje, zidentyfikowane na podstawie kodu w `db_tools/db_tools.py`:

| Kolekcja | Zawartość | Moduł zapisujący |
|---|---|---|
| `devices` | Aktualny stan każdego wykrytego urządzenia: adres IP, dane ogólne, interfejsy, metryki wydajnościowe, znacznik ostatniej aktywności (`last_seen`) | `PollerManager` → `db_tools.store_device()` |
| `metrics` | Historyczne, znacznikowane w czasie próbki metryk (CPU, RAM, ruch RX/TX) dla każdego urządzenia — podstawa wykresów w dashboardzie | `PollerManager` → `db_tools.build_metrics()` / `store_metrics()` |
| `logs` | Trwały log wszystkich zdarzeń/alertów wygenerowanych przez oba silniki detekcji | `PacketAnalyzer.py`, `SnmpAnalyzer.py` → `store_log_async()` |
| `telegram_subscribers` | Lista identyfikatorów czatów (`chat_id`) subskrybentów powiadomień Telegram | `notification_manager.py` |
| `packets` *(pomocnicza)* | Surowe dane pojedynczych pakietów — funkcja obecna w warstwie narzędziowej (`store_packet`), nieużywana aktywnie w głównym potoku przetwarzania | `db_tools.py` (funkcja narzędziowa, bez wywołań produkcyjnych) |

Połączenie z MongoDB w `db_tools/db_tools.py` odczytuje adres z `os.getenv("MONGO_URI")` — jeśli zmienna nie jest ustawiona w środowisku procesu, `pymongo.MongoClient(None)` przyjmuje domyślnie `mongodb://localhost:27017`.

### 3.4 Konfiguracja poprzez zmienne środowiskowe

Sekrety i parametry środowiskowe aplikacji (klucz sesyjny, hasło administracyjne, dane bota Telegram, adres bazy danych) nie są zapisane na stałe w kodzie źródłowym — repozytorium zawiera plik **`.env.example`**, będący szablonem zmiennych środowiskowych:

```
SECRET_KEY=...

MONGO_URI=mongodb://localhost:27017/NetPulse

TELEGRAM_BOT_TOKEN=...
TELEGRAM_BOT_PASSWORD=...

AUTH_PASSWORD=...
```

Wartości te są wczytywane przez klasę `Config` w `config.py` i udostępniane w aplikacji Flask jako `app.config[...]`:

| Parametr | Zmienna środowiskowa | Wartość domyślna |
|---|---|---|
| `SECRET_KEY` | `SECRET_KEY` | brak (wymagane) |
| `PERMANENT_SESSION_LIFETIME` | `SESSION_LIFETIME_DAYS` | 30 dni |
| `MONGO_URI` | `MONGO_URI` | `mongodb://localhost:27017/NetPulse` |
| `TELEGRAM_BOT_TOKEN` | `TELEGRAM_BOT_TOKEN` | brak (wymagane) |
| `TELEGRAM_BOT_PASSWORD` | `TELEGRAM_BOT_PASSWORD` | brak |
| `AUTH_PASSWORD` | `AUTH_PASSWORD` | brak (wymagane) |

`app.py` przy starcie weryfikuje obecność trzech kluczowych zmiennych (`SECRET_KEY`, `TELEGRAM_BOT_TOKEN`, `AUTH_PASSWORD`) i przerywa uruchomienie wyjątkiem `RuntimeError`, jeśli którejś z nich brakuje.

---

## 4. Struktura katalogów repozytorium

```
NetPulse-develop/
├── app.py                    # Punkt wejścia aplikacji
├── config.py                 # Konfiguracja aplikacji wczytywana ze zmiennych środowiskowych
├── requirements.txt          # Lista zależności Python z przypiętymi wersjami
├── .env.example               # Szablon zmiennych środowiskowych (sekrety, URI bazy danych)
├── .gitignore                # M.in. wyklucza plik .env z repozytorium
├── NetPulse.png               # Logo projektu
├── README.md                  # Podstawowy plik opisowy repozytorium
│
├── certs/
│   ├── cert.pem                # Certyfikat TLS (self-signed, deweloperski)
│   └── key.pem                  # Klucz prywatny TLS
│
├── core/
│   ├── auth.py                 # Globalny strażnik uwierzytelniania (before_request)
│   └── event_bus.py            # Magistrala zdarzeń (kolejki klientów SSE + powiadomienia)
│
├── routes/
│   ├── auth.py                  # Endpointy logowania/wylogowania/sesji
│   ├── devices.py               # Endpoint listy urządzeń
│   ├── events.py                # Endpoint strumienia zdarzeń (SSE)
│   ├── frontend.py              # Serwowanie głównego widoku SPA (dashboard.html)
│   ├── logs.py                  # Endpoint listy logów/alertów
│   └── metrics.py               # Endpoint metryk historycznych
│
├── services/
│   ├── devices_service.py       # Logika biznesowa pobierania urządzeń z bazy
│   ├── events_service.py        # Placeholder logiki alertów (nieużywany w routingu)
│   ├── logs_service.py          # Logika biznesowa pobierania logów z bazy
│   └── metrics_service.py       # Logika biznesowa agregacji metryk
│
├── serializers/
│   ├── devices_serializer.py    # Normalizacja/serializacja dokumentów urządzeń do JSON
│   ├── logs_serializer.py       # Serializacja logów (przepływ 1:1)
│   └── metrics_serializer.py    # Przeliczanie liczników kumulatywnych na wartości różnicowe
│
├── workers/
│   ├── main.py                  # Orkiestrator głównej pętli monitoringu
│   ├── MySnifferClass.py        # Sniffer pakietów (Scapy) + ekstrakcja cech
│   ├── SubnetScanner.py         # Skanowanie ARP podsieci
│   ├── PollerManager.py         # Zarządzanie cyklem odpytywania urządzeń
│   ├── SnmpPoller.py            # Klient SNMP (discovery + telemetria, tabela OID-ów)
│   ├── PacketAnalyzer.py        # Silnik detekcji anomalii na poziomie pakietów
│   ├── SnmpAnalyzer.py         # Silnik detekcji anomalii na poziomie telemetrii SNMP
│   ├── DevicesCRUD.py           # Samodzielne narzędzie CLI do edycji devices.json
│   └── devices.json             # Słownik mapowania opisów SNMP na typy urządzeń
│
├── db_tools/
│   ├── db_tools.py              # Warstwa dostępu do MongoDB (CRUD + narzędzia diagnostyczne)
│   ├── db_menu.py                # Interaktywne menu CLI do przeglądania bazy
│   └── db_temp.py                # Skrypt testowy (odwołuje się do nieistniejących funkcji)
│
├── helpers/
│   ├── notification_manager.py       # Integracja z Telegram Bot API
│   └── alert_cooldown_manager.py     # Mechanizm antyspamowy dla powtarzających się alertów
│
└── static/
    ├── dashboard.html           # Główny panel (dashboard) — SPA, responsywny (mobile + desktop)
    ├── login.html                # Strona logowania
    └── assets/
        └── NetPulse.png          # Zasoby graficzne frontendu
```

---

## 5. Szczegółowy opis modułów

Poniższy rozdział zawiera pełny, plik-po-pliku opis logiki zaimplementowanej w projekcie. Każdy moduł opisany jest pod kątem: odpowiedzialności, kluczowych funkcji/klas, przyjmowanych i zwracanych danych oraz sposobu integracji z resztą systemu.

### 5.1 Punkt wejścia aplikacji

#### 5.1.1 `app.py` — plik uruchomieniowy

Jest to jedyny punkt startowy całej aplikacji. Odpowiada za:

- utworzenie instancji aplikacji Flask oraz załadowanie jej konfiguracji z klasy `Config` (`app.config.from_object(Config)`),
- walidację obecności krytycznych zmiennych środowiskowych (`SECRET_KEY`, `TELEGRAM_BOT_TOKEN`, `AUTH_PASSWORD`),
- inicjalizację rozszerzenia `flask_pymongo.PyMongo`, udostępnianego globalnie jako `app.mongo`,
- włączenie obsługi CORS z dopuszczeniem poświadczeń (`supports_credentials=True`), niezbędnej do komunikacji z frontendem osadzonym pod innym adresem/portem,
- rejestrację wszystkich blueprintów (modułów tras): `logs_bp`, `devices_bp`, `metrics_bp`, `events_bp`, `auth_bp`, `frontend_bp`,
- rejestrację globalnego hooka `@app.before_request`, który przed każdym żądaniem wywołuje `auth_guard()` z modułu `core.auth`,
- w bloku `if __name__ == "__main__":` — wyciszenie logowania Flask/Werkzeug (dla czytelności logów IDS na konsoli), uruchomienie głównej pętli monitoringu (`workers.main.main`) w osobnym wątku demonicznym, uruchomienie podsystemu powiadomień Telegram (`start_telegram_system()`), a następnie start serwera WWW na porcie 8000, z wymuszonym szyfrowaniem TLS przy użyciu certyfikatów z katalogu `certs/`.

#### 5.1.2 `config.py`

Zawiera klasę `Config` z parametrami odczytywanymi ze zmiennych środowiskowych (przy pomocy `python-dotenv`), udostępnianymi następnie do `app.py` poprzez `app.config.from_object(Config)`:

- `SECRET_KEY` — klucz kryptograficzny do podpisywania ciasteczek sesji,
- `PERMANENT_SESSION_LIFETIME` — czas życia sesji trwałej (domyślnie 30 dni),
- `MONGO_URI` — adres połączenia z MongoDB (domyślnie `mongodb://localhost:27017/NetPulse`),
- `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE = "Lax"` — flagi bezpieczeństwa ciasteczka sesyjnego, ustawione na stałe,
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_PASSWORD` — dane dostępowe integracji z Telegramem,
- `AUTH_PASSWORD` — hasło logowania do panelu administracyjnego.

Moduł wywołuje `load_dotenv(".env.example")` przy imporcie — jawnie wskazując na plik szablonu zmiennych środowiskowych zamiast na plik `.env`.

### 5.2 Moduł `core` — rdzeń aplikacji

#### 5.2.1 `core/auth.py` — strażnik uwierzytelniania

Moduł implementuje funkcję `auth_guard()`, wywoływaną globalnie przed obsłużeniem każdego żądania HTTP (`@app.before_request`). Logika działania:

```python
PROTECTED = ("/devices", "/metrics", "/logs", "/events")

def auth_guard():
    path = request.path

    if path.startswith("/auth"):
        return

    if path == "/":
        if not session.get("authenticated", False):
            return redirect("/auth/login")
        return

    if path.startswith(PROTECTED):
        if not session.get("authenticated", False):
            return jsonify({"error": "unauthorized"}), 401
```

Reguła działania jest następująca:

1. Wszystkie ścieżki zaczynające się od `/auth` (logowanie, wylogowanie, sprawdzenie tożsamości) są zawsze przepuszczane bez weryfikacji — w przeciwnym razie niemożliwe byłoby zalogowanie się.
2. Żądanie strony głównej (`/`) jest przekierowywane na stronę logowania, jeśli użytkownik nie posiada aktywnej, uwierzytelnionej sesji.
3. Żądania do chronionych zasobów API (`/devices`, `/metrics`, `/logs`, `/events`) zwracają błąd `401 Unauthorized` w formacie JSON, jeśli sesja nie jest uwierzytelniona.
4. Wszystkie pozostałe ścieżki (np. `/static/...`) nie są objęte żadną blokadą — pozwala to na wczytanie plików statycznych (CSS, obrazki, logo) na stronie logowania bez konieczności bycia zalogowanym.

Mechanizm ten realizuje najprostszy możliwy model bezpieczeństwa: jedno hasło administracyjne + sesja oparta na ciasteczku, bez systemu ról, wielu kont użytkowników czy tokenów API.

#### 5.2.2 `core/event_bus.py` — magistrala zdarzeń

Serce mechanizmu powiadomień czasu rzeczywistego w systemie. Utrzymuje w pamięci procesu:

- `clients: list` — listę kolejek (`queue.Queue`) reprezentujących aktualnie podłączonych klientów SSE (przeglądarki nasłuchujące na `/events`),
- `clients_lock: threading.Lock` — blokadę chroniącą listę klientów przed równoczesną modyfikacją z wielu wątków,
- `notification_queue: queue.Queue` — oddzielną kolejkę FIFO, z której korzysta moduł powiadomień Telegram.

Udostępnia trzy funkcje:

- `register_client()` — tworzy nową kolejkę dla świeżo podłączonego klienta SSE i dodaje ją do globalnej listy `clients`,
- `unregister_client(q)` — usuwa kolejkę klienta po zamknięciu połączenia,
- `push_event(event)` — centralny punkt publikacji zdarzenia w systemie:

```python
def push_event(event):
    if not should_send_alert(event):
        return

    with clients_lock:
        for q in clients:
            q.put(event)

    if event['type'] != 'DATA_REFRESH_SIGNAL':
        notification_queue.put(event)
        push_event({'type': 'DATA_REFRESH_SIGNAL', 'source': 'System'})
```

Przed wysłaniem zdarzenia sprawdzana jest funkcja `should_send_alert()`, która zapobiega nadmiernemu generowaniu powiadomień. Jeśli zdarzenie zostanie zaakceptowane, trafia ono do kolejek wszystkich podłączonych klientów SSE. Dodatkowo, dla zdarzeń innych niż `DATA_REFRESH_SIGNAL`, jest przekazywane do kolejki powiadomień Telegram oraz generuje sygnał odświeżenia danych dla interfejsu webowego. Dzięki temu różne elementy systemu (np. panel WWW i bot Telegram) mogą reagować na to samo zdarzenie niezależnie od modułu, który je wygenerował.

### 5.3 Moduł `routes` — warstwa REST API (kontrolery)

Wszystkie trasy zaimplementowane są jako blueprinty Flask, zgodnie z klasycznym wzorcem: trasa (`routes/`) → logika biznesowa (`services/`) → serializacja odpowiedzi (`serializers/`).

#### 5.3.1 `routes/auth.py`

Definiuje blueprint `auth_bp` obsługujący cykl życia sesji użytkownika:

| Metoda | Ścieżka | Opis |
|---|---|---|
| GET | `/auth/login` | Zwraca statyczny plik `login.html`; jeśli sesja jest już uwierzytelniona, przekierowuje na `/` |
| POST | `/auth/login` | Weryfikuje przesłane hasło z wartością `current_app.config["AUTH_PASSWORD"]`; przy zgodności ustawia `session["authenticated"] = True` |
| POST | `/auth/logout` | Czyści sesję (`session.clear()`) i kasuje ciasteczko sesyjne |
| GET | `/auth/whoami` | Zwraca bieżący stan uwierzytelnienia sesji jako JSON |

Hasło administracyjne przechowywane jest jako zmienna środowiskowa i porównywane bezpośrednio (bez haszowania) z wartością przesłaną w żądaniu logowania. System nie implementuje odrębnych kont użytkowników ani ograniczenia liczby prób logowania. W kodzie widoczny jest też zakomentowany, alternatywny wariant endpointu `logout` oparty na metodzie GET — pozostawiony jako martwy kod.

#### 5.3.2 `routes/devices.py`

Pojedynczy endpoint `GET /devices`, delegujący całą logikę do `services.devices_service.get_devices_service()` i zwracający wynik jako JSON wraz z kodem statusu HTTP.

#### 5.3.3 `routes/metrics.py`

Pojedynczy endpoint `GET /metrics`, analogicznie delegujący do `services.metrics_service.get_metrics_service()`.

#### 5.3.4 `routes/logs.py`

Pojedynczy endpoint `GET /logs`, delegujący do `services.logs_service.get_logs_service()`.

#### 5.3.5 `routes/events.py` — strumień zdarzeń SSE

Najbardziej nietypowy technicznie kontroler w systemie. Endpoint `GET /events` zwraca odpowiedź typu `text/event-stream` (Server-Sent Events), generowaną przez generator `event_generator()`:

```python
def event_generator():
    q = register_client()
    try:
        while True:
            try:
                event = q.get(timeout=15)
                yield f"data: {json.dumps(event, default=str)}\n\n"
            except Empty:
                yield ":\n\n"
    except (GeneratorExit, BrokenPipeError, ConnectionResetError):
        return
    finally:
        unregister_client(q)
```

Mechanizm działania: przy nawiązaniu połączenia klient rejestruje własną kolejkę w magistrali zdarzeń (`register_client`). Następnie w nieskończonej pętli generator oczekuje maksymalnie 15 sekund na nowe zdarzenie w swojej kolejce. Jeśli zdarzenie się pojawi — jest serializowane do formatu JSON i wysyłane do przeglądarki zgodnie ze specyfikacją SSE (prefiks `data:` + podwójny znak nowej linii). Jeśli w ciągu 15 sekund nic się nie wydarzy, wysyłany jest komentarz `:\n\n` — technika keep-alive, zapobiegająca zamknięciu połączenia przez pośredniczące proxy/przeglądarkę z powodu bezczynności. Po zerwaniu połączenia (zamknięcie karty, restart przeglądarki) kolejka klienta jest usuwana z magistrali, aby uniknąć wycieku pamięci.

#### 5.3.6 `routes/frontend.py`

Pojedynczy endpoint `GET /`, zwracający statyczny plik `dashboard.html` — główny dashboard aplikacji (Single Page Application oparte na czystym HTML/CSS/JavaScript, bez frameworka frontendowego).

### 5.4 Moduł `services` — logika biznesowa

#### 5.4.1 `services/devices_service.py`

Funkcja `get_devices_service()` odpytuje kolekcję `devices` w MongoDB, wykluczając z wyniku urządzenia typu Switch (filtr `general_info.device_type: {"$nin": ["Switch"]}`). Wynik przekazywany jest do serializatora `serialize_devices()`. Świadome pominięcie przełączników sugeruje, że w warstwie prezentacji skupiono się na urządzeniach końcowych/routerach jako głównych obiektach monitoringu.

#### 5.4.2 `services/metrics_service.py`

Bardziej złożona logika: najpierw pobierany jest zbiór adresów IP urządzeń innych niż switche (`allowed_ip_set`), a następnie z kolekcji `metrics` pobierane są wyłącznie próbki należące do tych adresów, posortowane rosnąco po znaczniku czasu (`timestamp`). Wyniki grupowane są w słowniku (`defaultdict(list)`) kluczowanym adresem IP, a następnie przekazywane do `serialize_metrics()`, który przelicza surowe, kumulatywne liczniki na wartości przyrostowe.

#### 5.4.3 `services/logs_service.py`

Zwraca wszystkie dokumenty z kolekcji `logs`, posortowane malejąco po `timestamp` (od najnowszych), przekazywane bez większych przekształceń przez `serialize_logs()`.

#### 5.4.4 `services/events_service.py`

Plik zawiera funkcję `event_service()`, zwracającą zawsze tę samą, zaszytą na sztywno listę jednego przykładowego alertu (`"Device overheating"`), sterowaną warunkiem `if True:`. Funkcja ta nie jest wywoływana przez żaden zarejestrowany blueprint — jest to pozostałość po wczesnej fazie prototypowania mechanizmu alertów, zastąpiona później przez pełnoprawną magistralę zdarzeń (`core/event_bus.py`) i rzeczywisty strumień SSE.

### 5.5 Moduł `serializers` — transformacja danych wyjściowych

#### 5.5.1 `serializers/devices_serializer.py`

Odpowiada za przekształcenie surowego dokumentu MongoDB w ustrukturyzowany obiekt JSON gotowy do wyświetlenia w interfejsie. Kluczowe elementy logiki:

- **Wykrywanie aktywności urządzenia** (`detected`) — urządzenie uznawane jest za aktywne, jeśli różnica pomiędzy bieżącym czasem a znacznikiem `last_seen` jest mniejsza niż `DETECTION_WINDOW_SECONDS = 15` sekund. Funkcja poprawnie obsługuje strefy czasowe, uzupełniając `last_seen` o `timezone.utc`, jeśli dane z bazy nie zawierają informacji o strefie.
- **`serialize_general()`** — mapuje surowe pola SNMP (`sysName`, `sysDescr`, `device_type`, `vendor`, `status`) na czytelne pola wyjściowe.
- **`serialize_interfaces()`** — dla każdego interfejsu sieciowego urządzenia przelicza status operacyjny (`ifOperStatus == "1"` → `"up"`, w przeciwnym razie `"down"`) oraz konwertuje liczniki tekstowe SNMP na liczby całkowite (bajty/pakiety RX/TX, błędy RX/TX).
- **`serialize_performance()`** — implementuje logikę normalizacji metryk wydajnościowych niezależną od producenta urządzenia. Ponieważ różne platformy (Cisco, Linux) udostępniają zupełnie inne OID-y wydajnościowe, funkcja ta rozpoznaje dostępny zestaw pól i sprowadza go do wspólnego formatu:
  - `cpu_percent` — wyliczane różnymi metodami w zależności od dostępnych danych: z `cpu_idle` (100 − bezczynność), z `cpu_1min`, lub z `cpu_load_1m` (pomnożone ×100, jako przybliżenie obciążenia w skali procentowej),
  - `memory_used_bytes` — dla hostów linuksowych liczone jako `total − free − cached − buffered`; dla urządzeń Cisco jako suma zajętości puli procesora i puli I/O (`mem_pool_processor_used + mem_pool_io_used`).

Obie sekcje obliczeń są opakowane w bloki `try/except`, co zabezpiecza cały endpoint przed awarią w przypadku brakujących lub uszkodzonych danych telemetrycznych z pojedynczego urządzenia.

#### 5.5.2 `serializers/metrics_serializer.py`

Zawiera najważniejszą z perspektywy poprawności danych logikę w całym module serializatorów: przeliczanie liczników kumulatywnych SNMP na wartości przyrostowe (delty). Liczniki interfejsów sieciowych w SNMP (`ifInOctets`, `ifOutOctets`, `ifInUcastPkts`, `ifOutUcastPkts`) mają charakter rosnący (zliczają od uruchomienia urządzenia) — bez przeliczenia różnicowego wykres w dashboardzie pokazywałby stale rosnącą krzywą zamiast rzeczywistej przepustowości chwilowej. Algorytm dla każdej kolejnej próbki oblicza różnicę względem próbki poprzedniej (`max(0, wartość_bieżąca - wartość_poprzednia)`), przy czym funkcja `max(0, ...)` zabezpiecza przed ujemnymi wynikami w przypadku zawinięcia licznika (counter wrap) lub restartu urządzenia. Wartość pierwszej próbki w serii jest zawsze zerowa (brak punktu odniesienia).

#### 5.5.3 `serializers/logs_serializer.py`

Najprostszy z serializatorów — funkcja tożsamościowa, zwracająca listę logów bez żadnych przekształceń. Struktura dokumentu logu jest już w pełni gotowa do bezpośredniej konsumpcji przez frontend.

### 5.6 Moduł `workers` — silniki monitoringu i detekcji

Katalog `workers/` stanowi rdzeń funkcjonalny całego systemu IDS — to tutaj zaimplementowana jest cała logika akwizycji ruchu, odpytywania SNMP oraz — kluczowe dla charakteru projektu — reguły detekcji zagrożeń.

#### 5.6.1 `workers/main.py` — orkiestrator głównej pętli

Punkt centralny spinający wszystkie moduły warstwy monitoringu. Funkcja `start_app()` (uruchamiana w pętli `asyncio.run()` przez opakowującą ją funkcję `main()`) realizuje następujący scenariusz:

1. **Interaktywny wybór interfejsów** (`getInterfaceFromUser()`) — przy starcie systemu operator zostaje poproszony o wskazanie z listy dostępnych interfejsów sieciowych (`scapy.get_if_list()`) dwóch wartości: interfejsu do komunikacji SNMP oraz interfejsu portu mirroringu do przechwytywania pakietów. Podana wartość jest walidowana względem listy realnie istniejących interfejsów.
2. **Inicjalizacja komponentów** — utworzenie wspólnej kolejki międzyprocesowej (`multiprocessing.Queue`), uruchomienie snifera (`MySniffer`) na interfejsie mirroringu, uruchomienie analizatora pakietów (`MyAnalyzer`) z przekazaną definicją "bezpiecznej" sieci lokalnej (obliczaną jako maska /24 na bazie adresu IP interfejsu SNMP), utworzenie instancji pollera SNMP (`AsyncSNMPPoller`) oraz analizatora telemetrii (`SNMPTelemetryAnalyzer`).
3. **Inicjalna lista hostów** — zmienna `raw_hosts` inicjalizowana jest wartością placeholder (`[{'test': {'ip': '192.168.1.100'}}]`), której jedynym celem jest wymuszenie pełnej synchronizacji stanu przy pierwszym realnym skanowaniu sieci.
4. **Wczytanie tabeli mapowania urządzeń** — asynchroniczne wczytanie pliku `devices.json` do pamięci poprzez `PollerManager.load_lookup_table()`.
5. **Główna pętla nieskończona** — co `pool_cooldown = 10` sekund wykonywany jest jeden obrót pętli. Co `reset_k = 6` obrotów (a więc co ok. 60 sekund) wykonywane jest pełne ponowne skanowanie sieci (`scanForDevices`) w poszukiwaniu nowych lub zniknionych hostów; wykryte różnice (`added`/`removed`) są logowane, a zaktualizowana lista hostów przekazywana jest do `PollerManager.poll_devices()` w celu ponownego rozpoznania (discovery). Niezależnie od tego, w każdym obrocie pętli wywoływana jest funkcja `PollerManager.poll_metrics()`, odpowiedzialna za pobranie świeżych metryk wydajnościowych ze wszystkich już zarejestrowanych urządzeń.
6. **Obsługa przerwania** — funkcja `main()` przechwytuje `KeyboardInterrupt`, umożliwiając czyste zamknięcie aplikacji komunikatem "Zamykanie NetPulse...".

#### 5.6.2 `workers/MySnifferClass.py` — sniffer pakietów

Zawiera klasę `MySniffer`, cienką nakładkę na `scapy.AsyncSniffer`. Przy inicjalizacji sniffer natychmiast rozpoczyna nasłuch na wskazanym interfejsie (tryb `store=0` — pakiety nie są buforowane w pamięci Scapy, tylko przetwarzane "on the fly", co jest kluczowe dla wydajności przy dużym natężeniu ruchu). Destruktor klasy (`__del__`) zapewnia próbę czystego zatrzymania sniffera przy usunięciu obiektu.

Sercem modułu jest metoda `detailed_callback(packet)`, wywoływana dla każdego przechwyconego pakietu, ekstrahująca ustandaryzowany zestaw cech niezależnie od protokołu:

- warstwa L2: adres MAC źródłowy i docelowy,
- warstwa L3 (IP): adres IP źródłowy/docelowy,
- warstwa L4 — w zależności od wykrytego protokołu:
  - TCP: port źródłowy/docelowy oraz flagi TCP jako string (np. `"S"`, `"FPU"`, `"SA"`) — kluczowe dla wykrywania nietypowych kombinacji flag używanych w skanowaniu portów,
  - UDP: port źródłowy/docelowy,
  - ICMP: typ i kod ICMP, długość i entropia Shannona ładunku (payload),
  - ARP: kod operacji (`arp_op`), adres IP i MAC nadawcy zapytania/odpowiedzi ARP,
- ogólne metadane: znacznik czasu pakietu, całkowity rozmiar pakietu, długość i entropia ładunku danych.

Funkcja pomocnicza `shannon_entropy(data: bytes)` implementuje klasyczny wzór entropii Shannona:

$$H(X) = -\sum_i p(x_i)\log_2 p(x_i)$$

zwracając wartość z przedziału 0–8 bitów/bajt. Wysoka entropia ładunku (bliska 8) oznacza dane statystycznie nieodróżnialne od losowego szumu — charakterystyczne dla danych zaszyfrowanych, skompresowanych lub zakodowanych, co jest istotnym sygnałem przy wykrywaniu tunelowania danych w protokołach, które standardowo nie przenoszą dużych ładunków (np. ICMP — patrz reguła `ICMP_TUNNELING_SUSPECTED` w kolejnym podrozdziale). Skompletowany rekord danych trafia do wspólnej kolejki międzyprocesowej metodą nieblokującą (`put_nowait`), tak aby ewentualne spiętrzenie w analizatorze nie zatrzymywało procesu przechwytywania pakietów.

#### 5.6.3 `workers/SubnetScanner.py` — skanowanie sieci

Odpowiada za aktywne wykrywanie żywych hostów w podsieciach lokalnych, wykorzystując zapytania ARP (warstwa 2), co jest szybszą i mniej inwazyjną metodą niż tradycyjny skan ICMP/TCP. Logika:

1. `check_interface_families(interface)` — odczytuje z systemu operacyjnego (poprzez `netifaces`) wszystkie adresy IPv4 i IPv6 przypisane do wskazanego interfejsu wraz z ich maskami.
2. `scanForDevices(interface)` — dla każdego adresu IPv4 znalezionego na interfejsie wylicza notację CIDR sieci (`netaddr.IPNetwork`) i — o ile dana sieć nie została jeszcze przeskanowana w tym samym cyklu (zabezpieczenie `scanned_networks` przed duplikacją pracy przy wielu adresach z tej samej podsieci) — wywołuje `ARPscan()`.
3. `ARPscan(interface, ip_addr, netmask)` — konstruuje pakiet rozgłoszeniowy Ethernet + ARP (`Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cała_podsieć)`) i wysyła go poprzez `scapy.srp()` z limitem czasu 3 sekund, zbierając odpowiedzi w postaci par `{ip, mac}`.
4. `printDevices()` — funkcja pomocnicza formatująca wynik skanowania do czytelnej tabeli w konsoli (używana głównie w trybie diagnostycznym/manualnym).

#### 5.6.4 `workers/SnmpPoller.py` — klient SNMP (discovery + telemetria)

Moduł definiuje statyczną strukturę **`OIDS`**, zawierającą trzy grupy identyfikatorów SNMP:

- `base` — OID-y wykorzystywane wyłącznie w fazie discovery, aby nie przeciążać pętli telemetrycznej: `sysDescr`, `sysName`, `sysServices`,
- `performance` — OID-y wydajnościowe i detekcji anomalii, rozdzielone na rodziny urządzeń (obecnie dwie):
  - **`Cisco IOS/Nexus`**: `cpu_5sec`, `cpu_1min`, `cpu_5min` (CPU), `mem_pool_processor_used`, `mem_pool_io_used` (pamięć i pule),
  - **`Linux/Unix Server`**: `cpu_load_1m`, `cpu_load_5m` (obciążenie systemu), `cpu_user`, `cpu_system`, `cpu_idle` (podział CPU jądro/aplikacje/wolny procesor — kluczowe przy detekcji DDoS), `ram_total`, `ram_free`, `ram_cached`, `ram_buffered`, `swap_total`, `swap_free` (pamięć RAM i SWAP — wykrywanie wycieków pamięci), `total_processes` (liczba procesów — detekcja fork-bomb), `tcp_in_errors` (licznik uszkodzonych pakietów TCP),
- `interfaces` — uniwersalne OID-y statystyk portów, mierzone per-port dynamicznie: `ifNumber`, `ifDescr`, `ifOperStatus`, liczniki wolumetryczne (`ifInOctets`, `ifOutOctets`), liczniki pakietowe (`ifInUcastPkts`, `ifOutUcastPkts` — kluczowe przy floodzie małych pakietów), liczniki błędów (`ifInErrors`, `ifOutErrors`).

Rozpoznawanie producenta odbywa się poprzez słownik `VENDOR_MAP`, dopasowujący fragment tekstu `sysDescr` do nazwy platformy: `Cisco` → `Cisco IOS/Nexus`, `NX-OS` → `Cisco Nexus`, `Linux` → `Linux/Unix Server`, `MikroTik` → `MikroTik RouterOS`, `Windows` → `Windows Server`, `Huawei` → `Huawei VRP Platform`, `Juniper` → `Juniper Junos`. Tabela `OIDS["performance"]` zawiera jednak realne zestawy OID-ów wydajnościowych wyłącznie dla dwóch platform — `Cisco IOS/Nexus` oraz `Linux/Unix Server`. Urządzenia rozpoznane jako `MikroTik RouterOS`, `Windows Server`, `Huawei VRP Platform`, `Juniper Junos` czy `Cisco Nexus` są monitorowane na poziomie interfejsów (statystyki ruchu, status łącza), lecz nie są objęte regułami detekcji opartymi na CPU/RAM, ponieważ dla tych profili `vendor_metrics` wymaga rozbudowy.

Klasa **`AsyncSNMPPoller`** udostępnia dwie główne metody:

- **`get_device_identity(ip)`** — próbuje kolejno domyślnych społeczności SNMP (`public`, `cisco`, `admin`) do skutku, zapisując w `auth_cache` skuteczną kombinację community/transport dla danego adresu IP; identyfikuje producenta i liczbę interfejsów urządzenia.
- **`get_device_metrics(device_data)`** — pobiera metryki wydajnościowe właściwe dla rozpoznanej platformy, a następnie odpytuje porty interfejsów. Zakres indeksów portów do odpytania budowany jest heurystycznie: podstawowo porty 1–24 (typowe dla routerów), a dla urządzeń Cisco dodatkowo indeksy 101–116 (mapowanie modułu NM-16ESW) oraz indeks 5001 (typowy dla VLAN-u zarządzającego, np. `Vlan1`). W kodzie pozostawiony jest zakomentowany, alternatywny wariant odpytywania portów z limitem współbieżności (`asyncio.Semaphore(3)`), opisany jako potencjalnie szybszy, lecz obecnie nieaktywny.

#### 5.6.5 `workers/PollerManager.py` — zarządzanie cyklem odpytywania

Klasa `PollerManager` (współdzieląca stan globalny poprzez modułowe słowniki `monitored_devices` i `devices_lookup_table`) pełni funkcję koordynatora pomiędzy skanerem sieci, klientem SNMP, silnikiem detekcji telemetrii oraz warstwą bazodanową:

- **`load_lookup_table(path)`** — asynchronicznie wczytuje plik JSON zawierający mapowanie fragmentów opisu systemowego SNMP (`sysDescr`) na typ urządzenia (np. `"Switch"`, `"Router"`) i zapisuje go w module-globalnym słowniku `devices_lookup_table`. Obsługuje błędy braku pliku oraz błędnego formatu JSON, wypisując czytelny komunikat diagnostyczny bez przerywania działania aplikacji.
- **`resolve_device_type(sys_descr)`** (funkcja modułowa) — iteruje po wpisach słownika mapowania, sprawdzając (bez rozróżniania wielkości liter), czy dany klucz stanowi podciąg opisu systemowego zwróconego przez urządzenie; w razie braku dopasowania zwraca `"Unknown"`.
- **`poll_devices(poller, raw_hosts)`** — dla każdego hosta wykrytego przez skaner ARP równolegle (`asyncio.gather`) wykonuje zapytanie identyfikacyjne SNMP (`poller.get_device_identity`). Urządzenia odpowiadające na SNMP (`status == 'up'`) są klasyfikowane pod względem typu i dodawane do globalnego rejestru `monitored_devices`, a ich dane ogólne zapisywane trwale w MongoDB (`store_device`). Urządzenia nieosiągalne są mimo to odnotowywane w bazie (z samym statusem), co pozwala na śledzenie historii dostępności hosta.
- **`poll_metrics(poller, SnmpAnalyzer)`** — dla wszystkich aktualnie monitorowanych urządzeń równolegle pobiera świeże metryki wydajnościowe i statystyki interfejsów. Dla każdego urządzenia z poprawną odpowiedzią: a) aktualizuje dokument urządzenia w bazie, b) buduje ujednolicony rekord metryk czasowych (`build_metrics`) i zapisuje go jako nowy wpis historyczny, c) asynchronicznie zleca analizę telemetryczną (`SnmpAnalyzer.analyze_metrics`) w poszukiwaniu anomalii. Po zakończeniu cyklu emitowany jest sygnał `DATA_REFRESH_SIGNAL` do magistrali zdarzeń, informujący podłączone przeglądarki, że dostępne są świeże dane do pobrania przez REST API.

### 5.7 Silniki detekcji anomalii — serce systemu IDS

Ten podrozdział opisuje najistotniejszą z punktu widzenia charakteru projektu (jako systemu IDS) logikę: reguły wykrywania zagrożeń zaimplementowane w plikach `workers/PacketAnalyzer.py` oraz `workers/SnmpAnalyzer.py`. Każda reguła generuje ustandaryzowaną strukturę zdarzenia (`event`) o polach: `timestamp`, `type`, `source`, `threatLevel` (poziom zagrożenia: `low` / `medium` / `high` / `critical`), `ip` oraz opisowy `message`, publikowaną poprzez `push_event()` i trwale zapisywaną w bazie (`store_log_async()`).

#### 5.7.1 `workers/PacketAnalyzer.py` — analiza ruchu pakietowego w czasie rzeczywistym

Moduł definiuje trzy współpracujące ze sobą klasy: `MyAnalyzer` (główna pętla przetwarzania i reguły "sygnaturowe"), `StructuralAnomalyDetector` (reguły statystyczne oparte na strukturze ruchu TCP w oknach czasowych) oraz `MovingAverageDetector` (detekcja wolumetryczna oparta na średnich kroczących).

##### 5.7.1.1 Klasa `MyAnalyzer` — główna pętla i reguły sygnaturowe

Klasa uruchamia asynchroniczną pętlę (`start_loop`) pobierającą pakiety z kolejki międzyprocesowej (blokująco, w osobnym wątku poprzez `asyncio.to_thread`, aby nie blokować pętli zdarzeń) i przekazującą każdy z nich do `_process_rules()`. Równolegle uruchamiane są w tle dwa niezależne zadania analityczne: pętla `StructuralAnomalyDetector.analysis_loop()` oraz `MovingAverageDetector.check_anomaly()`.

Zaimplementowane reguły detekcji na poziomie pojedynczego pakietu (`_process_rules`):

1. **XMAS Scan** (`TCP_XMAS_SCAN`, poziom: `medium`) — wykrywana jest kombinacja flag TCP FIN + PSH + URG ustawionych jednocześnie. Jest to technika skanowania portów wykorzystująca niestandardową kombinację flag, mającą na celu ominięcie prostych systemów firewall poprzez wywołanie nietypowej reakcji stosu TCP/IP celu.
2. **NULL Scan** (`TCP_NULL_SCAN`, poziom: `medium`) — wykrywany jest pakiet TCP bez żadnych ustawionych flag. Podobnie jak skan XMAS, jest to technika stealth-scanningu wykorzystywana do rekonesansu reguł zapory sieciowej bez inicjowania pełnego trójstronnego uzgadniania połączenia.
3. **SYN-FIN Anomaly** (`TCP_SYN_FIN_ANOMALY`, poziom: `medium`) — wykrywana jest jednoczesna obecność flag SYN i FIN w tym samym pakiecie — kombinacja niewystępująca w prawidłowej komunikacji TCP, typowa dla narzędzi do skanowania stealth lub manipulacji pakietami.
4. **Tunelowanie / eksfiltracja przez ICMP** (`ICMP_TUNNELING_SUSPECTED`, poziom: `high`) — reguła łączy dwa kryteria jednocześnie: długość ładunku pakietu ICMP przekraczającą 200 bajtów oraz entropię Shannona ładunku powyżej 5,5 (w skali 0–8). Standardowy ruch ping ma mały, przewidywalny ładunek; duży pakiet ICMP o wysokiej entropii silnie sugeruje przesyłanie zakodowanych/zaszyfrowanych danych w tunelu ICMP.
5. **ARP Spoofing** (`ARP_SPOOFING_DETECTED`, poziom: `critical`) — moduł utrzymuje pamięć podręczną `arp_cache` (typu `defaultdict(deque(maxlen=2))`) przechowującą dla każdego adresu IP dwa ostatnio zaobserwowane adresy MAC skojarzone z tym IP w odpowiedziach ARP (`arp_op == 2`). Jeżeli nowo zaobserwowany adres MAC różni się od poprzednio zapamiętanego dla tego samego IP, zgłaszany jest alarm krytyczny.
6. **Dostęp do portów krytycznych** (`SUSPICIOUS_CRITICAL_PORT_ACCESS`, poziom: `low`) — monitorowany jest ruch kierowany do portów 21 (FTP), 22 (SSH), 23 (Telnet), 445 (SMB). Reguła świadomie pomija ruch pochodzący z sieci lokalnej (`safe_network`, obliczanej jako maska /24 wokół adresu interfejsu SNMP), ograniczając liczbę fałszywych alarmów generowanych przez normalny ruch administracyjny wewnątrz sieci, a skupiając się na próbach dostępu z zewnątrz.

##### 5.7.1.2 Klasa `MovingAverageDetector` — detekcja wolumetrycznego DDoS

Implementuje klasyczny algorytm porównania krótkoterminowej i długoterminowej średniej kroczącej liczby pakietów na sekundę (PPS):

- `long_window_sec = 300` (5 minut) — okno definiujące "normalny" poziom ruchu w sieci (baseline),
- `short_window_sec = 5` — okno obserwujące aktualny, bieżący poziom ruchu,
- `multiplier = 20.0` — krotność, o jaką aktualny ruch musi przewyższać baseline, aby uznać go za anomalię.

Co sekundę (`check_anomaly`) usuwane są z obu buforów (`deque`) znaczniki czasowe starsze niż odpowiednie okno, po czym wyliczane są średnie PPS dla obu okien. Alarm `VOLUMETRIC_DDOS_DETECTED` (poziom: `critical`) zostaje wygenerowany, gdy jednocześnie: a) długoterminowa średnia przekracza próg istotności (`avg_long_pps > 5`, eliminacja fałszywych alarmów przy znikomym ruchu bazowym) oraz b) krótkoterminowy PPS przekracza długoterminowy o więcej niż zdefiniowaną krotność (domyślnie 20×). Wbudowany mechanizm `anti_alert_spam` zapewnia, że alert zostanie wygenerowany tylko raz na początku epizodu ataku, a nie w kółko co sekundę przez cały czas jego trwania — stan resetuje się automatycznie, gdy ruch wraca do normy.

##### 5.7.1.3 Klasa `StructuralAnomalyDetector` — detekcja strukturalna ataków TCP

Analizuje w cyklicznych oknach 5-sekundowych (`analysis_loop`) trzy niezależne wskaźniki struktury ruchu TCP, agregowane na bieżąco metodą `process_tcp_metrics()`:

1. **SYN Flood — wariant "asymetryczny"** (`SYN_FLOOD_DETECTED`, poziom: `critical`) — wyliczany jest stosunek liczby pakietów z flagą SYN do liczby pakietów z flagą ACK w danym oknie czasowym. Jeżeli stosunek ten przekracza próg `max_syn_ack_ratio = 5.0` oraz bezwzględna liczba pakietów SYN w oknie wynosi co najmniej 150, zgłaszany jest alarm — sygnalizujący klasyczny SYN Flood, w którym serwer zalewany jest żądaniami połączenia bez odpowiadających im potwierdzeń.
2. **SYN Flood — wariant "wysokiego wolumenu"** (`SYN_FLOOD_HIGH_VOLUME`, poziom: `high`) — obsługuje przypadek, w którym serwer atakowany skutecznie odpowiada na napływające żądania (stosunek SYN/ACK pozostaje w normie), lecz sama liczba pakietów SYN w oknie przekracza 500 — co wciąż wskazuje na agresywny, anormalny wolumen żądań połączenia.
3. **Rozproszony DDoS** (`DISTRIBUTED_DENIAL_OF_SERVICE`, poziom: `critical`) — analizowany jest stosunek liczby unikalnych adresów IP źródłowych do całkowitej liczby pakietów w oknie (`ip_dispersion_ratio`). Jeśli ten stosunek przekracza próg `max_unique_ip_ratio = 0.7` przy jednoczesnym wolumenie ruchu powyżej 500 pakietów w oknie, zgłaszany jest alarm sugerujący, że ruch pochodzi od bardzo dużej liczby odrębnych hostów jednocześnie — charakterystyczny wzorzec ataku rozproszonego (DDoS realizowanego przez botnet).

Każdy z trzech wskaźników posiada niezależną flagę antyspamową (`SYNACK1_anti_alert_spam`, `SYNACK2_anti_alert_spam`, `unique_ip_anti_alert_spam`), zapewniającą, że alert generowany jest jednorazowo na początek epizodu, z automatycznym resetem po powrocie ruchu do normy.

#### 5.7.2 `workers/SnmpAnalyzer.py` — analiza anomalii telemetrii SNMP

Klasa `SNMPTelemetryAnalyzer` utrzymuje w pamięci (`states: defaultdict`) poprzedni stan wydajnościowy oraz stan interfejsów dla każdego monitorowanego adresu IP, co pozwala na wykrywanie anomalii różnicowych (zmiana w czasie), a nie tylko przekroczeń wartości bezwzględnych. Analiza podzielona jest na dwie równoległe ścieżki (`asyncio.gather`): `_analyze_performance()` oraz `_analyze_interfaces()`.

##### 5.7.2.1 Reguły dla sektora Linux/Unix Server

Aktywowane, gdy dostępne są pola telemetryczne charakterystyczne dla agenta SNMP Net-SNMP na systemach Linux (`cpu_system`, `cpu_load_1m`):

- **Wyczerpanie zasobów / Fork-Bomb** (`RESOURCE_EXHAUSTION`, poziom: `critical`) — alarm zgłaszany, gdy liczba procesów systemowych (`total_processes`) przekracza 300 lub średnie obciążenie systemu w ostatniej minucie (`load_1m`) przekracza 12.0. Wzorzec ten odpowiada zarówno atakom typu fork bomb, jak i błędnie działającej/złośliwej aplikacji gwałtownie mnożącej procesy.
- **Wygłodzenie pamięci RAM** (`RESOURCE_STARVATION`, poziom: `critical`) — rzeczywiste zużycie RAM obliczane jest jako `ram_total − ram_free − ram_cached − ram_buffered`, a alarm generowany jest, gdy procentowe wykorzystanie pamięci przekracza 90% lub suma pamięci wolnej i cache spada poniżej 55 000 (jednostka zgodna z OID, zwykle KB). Dodatkowo reguła sprawdza, czy jednocześnie zmniejsza się ilość wolnej przestrzeni SWAP względem poprzedniego pomiaru (`swap_changed`), co potwierdza aktywne swapowanie i pogłębia diagnozę poważnego wyczerpania pamięci.
- Dodatkowo w kodzie obecna jest (obecnie zakomentowana, a więc wyłączona z działania) reguła detekcji powolnego skanowania portów (Stealth / Slow Port Scan) oparta na przyroście licznika błędnych pakietów TCP (`tcp_in_errors`) przy jednoczesnym niskim obciążeniu CPU hosta — pozostawiona w kodzie jako gotowy, ale świadomie wyłączony (ze względu na zbyt dużą liczbę fałszywych alarmów w testach) element do dalszego dopracowania.

##### 5.7.2.2 Reguły dla sektora Cisco (routery / switche)

Aktywowane, gdy dostępne jest pole `cpu_5sec` (charakterystyczne dla drzewa MIB CISCO-PROCESS-MIB):

- **Wyczerpanie płaszczyzny sterowania** (`CONTROL_PLANE_EXHAUSTION`, poziom: `critical`) — alarm zgłaszany, gdy pięciosekundowe obciążenie CPU urządzenia (`cpu_5sec`) przekracza próg 60%. Wysokie obciążenie CPU routera/switcha może uniemożliwić prawidłowe przetwarzanie ruchu sterującego (routing, ARP, protokoły dynamiczne), prowadząc do niestabilności całej sieci.
- **Podejrzany wyciek pamięci** (`MEMORY_LEAK_SUSPECTED`, poziom: `high`) — porównywana jest zajętość puli pamięci procesora (`mem_pool_processor_used`) względem poprzedniego pomiaru. Jeśli przyrost pamięci przekracza 12 milionów bajtów w ciągu jednego interwału (10 sekund) przy jednocześnie niskim obciążeniu CPU (poniżej 15%), sugeruje to nienaturalny wyciek pamięci niezwiązany ze zwiększonym ruchem.

##### 5.7.2.3 Reguły wspólne dla wszystkich typów urządzeń (poziom interfejsów)

Realizowane w `_analyze_interfaces()`, niezależnie od producenta urządzenia:

- **Link Flapping** (`LINK_FLAPPING`, poziom: `low`) — wykrywana jest każda zmiana statusu operacyjnego interfejsu (`ifOperStatus`) względem poprzedniego pomiaru (np. z `up` na `down` i odwrotnie). Częste przełączanie stanu łącza sygnalizuje niestabilność fizyczną (uszkodzony kabel, port) lub może być efektem celowego sabotażu/zakłócania łącza.
- **Anomalny ruch wychodzący / eksfiltracja danych** (`ANOMALOUS_OUTBOUND_TRAFFIC`, poziom: `high`) — porównywany jest przyrost liczby bajtów wysłanych przez dany interfejs (`ifOutOctets`) względem poprzedniego pomiaru. Przyrost przekraczający 15 milionów bajtów w jednym interwale (z pominięciem interfejsu pętli zwrotnej `lo`) zgłaszany jest jako potencjalna nieautoryzowana eksfiltracja danych lub nietypowo duży transfer danych z monitorowanego hosta.

### 5.8 Pomocnicze narzędzia zarządzania danymi

#### 5.8.1 `workers/DevicesCRUD.py`

Samodzielne, interaktywne narzędzie wiersza poleceń (CLI) do zarządzania zawartością pliku `devices.json` (słownika mapowania fragmentów opisu SNMP na typ urządzenia), niezależne od głównej aplikacji. Udostępnia menu tekstowe z opcjami: wyświetlenia wszystkich wpisów (`show_devices`), dodania lub modyfikacji wpisu (`add_or_update_device` — z automatycznym domykaniem klucza w nawiasy poprzez `format_key()`) oraz usunięcia wpisu z potwierdzeniem operacji (`delete_device`). Narzędzie operuje na pliku `devices.json` znajdującym się w katalogu roboczym uruchomienia skryptu (stała `FILE_NAME = "devices.json"`), co administrator powinien mieć na uwadze przy uruchamianiu go z innego katalogu niż `workers/`.

#### 5.8.2 `workers/devices.json`

Statyczny słownik JSON, wiążący charakterystyczne fragmenty pola `sysDescr` (opis systemowy zwracany przez SNMP, tu w formie nazw obrazów systemowych urządzeń emulowanych/testowych, np. z platformy GNS3/EVE-NG) z ogólnym typem urządzenia:

```json
{
  "(C3640-A3JS-M)": "Switch",
  "(I86BI_LINUXL2-ADVENTERPRISEK9-M)": "Switch",
  "(C7200-ADVENTERPRISEK9-M)": "Router"
}
```

#### 5.8.3 `db_tools/db_tools.py` — warstwa dostępu do bazy danych

Centralny moduł komunikacji z MongoDB, łączący się bezpośrednio (poza kontekstem aplikacji Flask) poprzez natywnego klienta `pymongo.MongoClient`, którego adres odczytywany jest ze zmiennej środowiskowej `MONGO_URI`. Udostępnia dwie grupy funkcji:

**Funkcje zapisu (używane produkcyjnie przez `workers/*`)**:

- `store_device(ip, general_info, performance, interfaces)` — wykonuje operację `update_one` z opcją `upsert=True` na kolekcji `devices`, aktualizując tylko przekazane pola (wzorzec częściowej aktualizacji dokumentu) oraz zawsze odświeżając znacznik `last_seen`. Pole `ip` jest zapisywane wyłącznie przy pierwszym utworzeniu dokumentu (`$setOnInsert`), co zapobiega nadpisywaniu klucza głównego przy kolejnych aktualizacjach.
- `store_log` / `store_log_async` — zapis pojedynczego zdarzenia do kolekcji `logs`; wariant asynchroniczny (`store_log_async`) deleguje operację blokującą do puli wątków wykonawczych (`loop.run_in_executor`), tak aby zapis do bazy nie blokował pętli zdarzeń asyncio używanej przez silniki detekcji.
- `build_metrics(ip, performance, interfaces)` — funkcja czysto obliczeniowa (bez efektów ubocznych na bazie), konstruująca ujednolicony rekord metryk czasowych: normalizuje CPU/RAM analogicznie jak serializator urządzeń, a następnie sumuje statystyki wszystkich interfejsów danego urządzenia do zagregowanych wartości całkowitych (`rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, liczba interfejsów aktywnych/nieaktywnych).
- `store_metrics(metrics)` — zapisuje pojedynczy, gotowy rekord metryk (zwrócony przez `build_metrics`) jako nowy dokument w kolekcji `metrics` (model append-only, każda próbka to osobny dokument — umożliwia to budowę historii czasowej i wykresów).
- `store_subscriber` / `get_subscribers` / `remove_subscriber` — zarządzanie listą subskrybentów bota Telegram w kolekcji `telegram_subscribers`.
- `clear_database()` — funkcja narzędziowa usuwająca (`drop()`) wszystkie kolekcje bazy danych — przeznaczona wyłącznie do celów diagnostycznych/resetu środowiska testowego, dostępna z poziomu menu `db_menu.py`.

**Funkcje diagnostyczne (używane tylko z poziomu CLI, nie w API produkcyjnym)**: `display_packets`, `display_devices`, `display_logs`, `display_metrics`, `display_subscribers` — każda z nich wypisuje w konsoli (przy pomocy `pprint`) pełną zawartość odpowiedniej kolekcji, ponumerowaną i oddzieloną liniami separatorów. Funkcje te służą wyłącznie do ręcznej inspekcji stanu bazy przez administratora/programistę.

#### 5.8.4 `db_tools/db_menu.py`

Proste, tekstowe menu CLI (`input()` w pętli) spinające funkcje diagnostyczne z `db_tools.py` w jeden interaktywny interfejs administracyjny, uruchamiany niezależnie od głównej aplikacji webowej (`python db_menu.py`).

#### 5.8.5 `db_tools/db_temp.py`

Skrypt testowy importujący funkcje `store_router` i `store_host`, które nie istnieją w aktualnej wersji `db_tools.py` (moduł ten definiuje wyłącznie `store_device`, brak jest osobnych funkcji dla routerów i hostów). Plik ten jest jawnie zdezaktualizowanym artefaktem wcześniejszego etapu rozwoju bazy danych (poprzedzającego ujednolicenie modelu urządzeń pod wspólną kolekcję `devices`) i w obecnym stanie repozytorium nie jest uruchamialny bez błędu importu.

### 5.9 Moduł `helpers` — funkcje pomocnicze i integracje

#### 5.9.1 `helpers/notification_manager.py` — integracja z Telegram Bot API

Moduł implementuje kompletny, samodzielny mechanizm dystrybucji alertów IDS poprzez komunikator Telegram, działający w dwóch niezależnych wątkach demonicznych uruchamianych przez `start_telegram_system()`:

- **`telegram_polling_loop()`** — realizuje technikę long pollingu API Telegrama (`getUpdates`), w nieskończonej pętli (co 2 sekundy) odpytując o nowe wiadomości przychodzące do bota. Obsługiwane są dwie komendy tekstowe:
  - `/subscribe <hasło>` — jeśli podane hasło zgadza się ze skonfigurowaną wartością (`Config.TELEGRAM_BOT_PASSWORD`), identyfikator czatu (`chat_id`) zostaje zapisany w bazie jako autoryzowany subskrybent (`store_subscriber`); w przeciwnym razie próba jest odrzucana i logowana jako nieautoryzowana,
  - `/unsubscribe` — usuwa dany `chat_id` z listy subskrybentów (`remove_subscriber`).
- **`send_telegram_alert(event)`** — formatuje zdarzenie do czytelnej wiadomości tekstowej (`format_event`) i wysyła je (przez REST API `sendMessage`) do wszystkich aktualnie zarejestrowanych subskrybentów.
- **`telegram_worker()`** — wątek konsumujący zdarzenia z `notification_queue` (tej samej kolejki, do której zapisuje `core/event_bus.push_event()`) i przekazujący je do wysyłki.
- **`format_event(event)`** — buduje czytelny szablon wiadomości zawierający: poziom zagrożenia, typ zdarzenia, źródło detekcji (`packet_analysis` / `snmp`), adres IP oraz znacznik czasu automatycznie skonwertowany do polskiej strefy czasowej (`Europe/Warsaw`, przy pomocy `to_warsaw_time()` i modułu `zoneinfo`), niezależnie od tego, czy znacznik w bazie zapisany jest jako obiekt `datetime` czy jako string.

Token dostępowy bota Telegram (`TOKEN`) oraz hasło subskrypcji (`SECRET_PASSWORD`) pobierane są z klasy `Config` (a więc ze zmiennych środowiskowych) — moduł nie zawiera żadnych wartości sekretnych zapisanych jawnym tekstem.

#### 5.9.2 `helpers/alert_cooldown_manager.py` — mechanizm antyspamowy alertów

Prosty, ale istotny komponent — funkcja `should_send_alert(event)` decyduje, czy dane zdarzenie powinno zostać faktycznie rozesłane, czy odrzucone jako duplikat w krótkim odstępie czasu. Logika: dla klucza złożonego z pary `(typ_zdarzenia, adres_ip)` zapisywany jest znacznik czasu ostatniego wysłania takiego alertu (`last_alerts`, chroniony blokadą `last_alerts_lock`). Jeśli od ostatniego wysłania minęło mniej niż `ALERT_COOLDOWN` (5 sekund) sekund, zdarzenie jest wyciszane. Sygnały wewnętrzne typu `DATA_REFRESH_SIGNAL` są zawsze przepuszczane bezwarunkowo, niezależnie od cooldownu.

### 5.10 Warstwa prezentacji (frontend)

Interfejs użytkownika NetPulse zrealizowany jest jako lekka aplikacja jednostronowa (SPA), napisana w czystym HTML, CSS i JavaScript (bez frameworków typu React/Vue/Angular ani zewnętrznych bibliotek wykresów — wizualizacje danych rysowane są ręcznie na elemencie `<canvas>`). Estetyka utrzymana jest w konwencji "terminala" — ciemne tło, monospaced font, akcenty w kolorze cyan — nawiązującej wizualnie do profesjonalnych narzędzi sieciowych/bezpieczeństwa (NOC/SOC dashboard). Interfejs jest w pełni responsywny — zestaw reguł `@media` (progi 400px, 600px, 900px) dostosowuje układ do urządzeń mobilnych.

#### 5.10.1 `static/login.html`

Samodzielna strona logowania, niezależna od głównego bundla aplikacji. Zawiera formularz z polem hasła (z opcją podglądu wpisywanego tekstu — przełącznik z ikoną oka), który po przesłaniu wykonuje żądanie `fetch` typu POST do endpointu `/auth/login` (z opcją `credentials: "include"`, niezbędną do prawidłowego przekazania i zapisania ciasteczka sesyjnego). W przypadku powodzenia użytkownik jest przekierowywany na stronę główną aplikacji; w przeciwnym razie wyświetlany jest komunikat błędu ("INVALID PASSWORD").

#### 5.10.2 `static/dashboard.html` — główny dashboard

Najbardziej rozbudowany plik frontendowy projektu, realizujący pełny panel operacyjny administratora, podzielony na dwie główne zakładki nawigacyjne:

**Zakładka „DEVICES” (urządzenia):**

- Panel boczny z listą wykrytych urządzeń (`#device-list`), pobieraną z endpointu `/devices` oraz aktualizowaną w czasie rzeczywistym. Na urządzeniach mobilnych panel ten chowa się do wysuwanej szuflady, otwieranej przyciskiem hamburgera (`#btn-hamburger`).
- Panel szczegółów urządzenia, zawierający sekcje:
  - **GENERAL** — nazwa, adres IP, status, producent, opis systemowy, typ urządzenia,
  - **PERFORMANCE** — bieżące zużycie CPU/RAM (z możliwością przełączenia widoku na dane surowe SNMP poprzez przycisk `RAW`),
  - **INTERFACES** — lista interfejsów sieciowych wraz ze statusem (up/down) i licznikami ruchu,
  - **CHARTS** — sześć niezależnych wykresów czasowych rysowanych na płótnie `<canvas>`: CPU, RAM, RX bytes, TX bytes, RX packets, TX packets, każdy z własną funkcją formatowania etykiet (`formatBytes`, formatowanie procentowe, formatowanie z separatorem tysięcy) i możliwością regulacji liczby wyświetlanych punktów danych (`setChartPoints`).
- Panel alertów (`#alerts`) wyświetlający na bieżąco napływające zdarzenia z magistrali SSE; na urządzeniach mobilnych dostępny jako osobna wysuwana szuflada, otwierana przyciskiem `#btn-alerts-toggle`.

**Zakładka „LOGS” (dziennik zdarzeń):**

- Pełna, filtrowalna lista wszystkich zarejestrowanych alertów historycznych, pobierana z `/logs`.
- Zestaw filtrów: po adresie IP (`#filter-ip`), po poziomie zagrożenia (`#filter-level`), po typie zdarzenia (`#filter-type`) oraz swobodne wyszukiwanie tekstowe (`#filter-search`), wraz z licznikiem wyświetlanych wyników (`#logs-count`).

**Panel nawigacyjny** zawiera również przycisk wylogowania (`#logout-btn`), który wywołuje `POST /auth/logout` i przekierowuje użytkownika na stronę logowania.

**Mechanizm danych na żywo:** aplikacja nawiązuje połączenie SSE poprzez `new EventSource(API_BASE + "/events")`, dzięki czemu każde nowe zdarzenie wygenerowane przez backend (alert IDS lub sygnał odświeżenia danych) trafia natychmiast do przeglądarki bez konieczności odpytywania (pollingu) API w pętli. Po otrzymaniu sygnału `DATA_REFRESH_SIGNAL` interfejs samodzielnie odświeża dane urządzeń/metryk/logów poprzez ponowne zapytania REST.

Adres API backendu jest w obu plikach frontendowych zapisany na stałe jako stała `API_BASE = "https://172.16.253.1:8000"` — co wskazuje, że domyślnie panel skonfigurowany jest do pracy w konkretnym środowisku laboratoryjnym/testowym i wymaga dostosowania tego adresu przy wdrożeniu na innym hoście lub w innej sieci.

#### 5.10.3 `static/assets/` i `certs/`

Katalog `static/assets/` zawiera zasoby graficzne (logo `NetPulse.png`) używane przez strony `login.html` i `dashboard.html`. Katalog `certs/` zawiera parę plik klucza prywatnego i certyfikatu X.509 (`key.pem`, `cert.pem`) używaną do uruchomienia serwera Flask w trybie HTTPS — status ważności tego certyfikatu opisano w rozdziale.

---

## 6. Model danych

### 6.1 Kolekcja `devices`

Reprezentuje aktualny (najświeższy znany) stan pojedynczego urządzenia sieciowego. Dokument identyfikowany jest unikalnym adresem `ip` i aktualizowany metodą upsert przy każdym cyklu odpytywania.

| Pole | Typ | Opis |
|---|---|---|
| `ip` | string | Adres IPv4 urządzenia (klucz identyfikujący) |
| `last_seen` | datetime (UTC) | Znacznik czasu ostatniej pomyślnej aktualizacji danych urządzenia |
| `general_info` | object | Dane z fazy discovery: `status`, `vendor`, `sysName`, `sysDescr`, `device_type`, `sysServices`, `ifNumber` |
| `performance` | object | Surowe metryki wydajnościowe SNMP, zależne od rodziny urządzenia (patrz `SnmpPoller.py`) |
| `interfaces` | array | Lista obiektów opisujących poszczególne interfejsy: `if_number`, `ifDescr`, `ifOperStatus`, liczniki `ifInOctets`/`ifOutOctets`/`ifInUcastPkts`/`ifOutUcastPkts`/`ifInErrors`/`ifOutErrors` |

### 6.2 Kolekcja `metrics`

Historyczny, przyrostowy (append-only) zapis próbek metryk — podstawa danych do wykresów czasowych.

| Pole | Typ | Opis |
|---|---|---|
| `ip` | string | Adres urządzenia, którego dotyczy próbka |
| `timestamp` | datetime (UTC) | Moment pobrania próbki |
| `cpu` | float / null | Znormalizowane zużycie CPU (%) |
| `ram` | float / null | Znormalizowane zużycie pamięci (jednostka zależna od źródła — bajty/KB) |
| `rx_bytes`, `tx_bytes` | int | Suma bajtów odebranych/wysłanych przez wszystkie interfejsy urządzenia w danej próbce |
| `rx_packets`, `tx_packets` | int | Suma pakietów odebranych/wysłanych |
| `interfaces_up`, `interfaces_down` | int | Liczba interfejsów w stanie aktywnym / nieaktywnym |

### 6.3 Kolekcja `logs`

Trwały dziennik wszystkich alertów bezpieczeństwa wygenerowanych przez oba silniki detekcji.

| Pole | Typ | Opis |
|---|---|---|
| `timestamp` | datetime (UTC) | Moment wykrycia zdarzenia |
| `type` | string | Typ zdarzenia — jeden ze zidentyfikowanych typów, patrz tabela zbiorcza poniżej |
| `source` | string | Źródło detekcji: `packet_analysis` (silnik pakietowy) lub `snmp` (silnik telemetryczny) |
| `threatLevel` | string | Poziom zagrożenia: `low`, `medium`, `high`, `critical` |
| `ip` | string | Adres IP powiązany ze zdarzeniem (cel lub urządzenie, którego dotyczy anomalia) |
| `message` | string | Pełny, czytelny dla człowieka opis wykrytej anomalii |

#### 6.3.1 Zbiorcza tabela wszystkich typów zdarzeń IDS

| Typ zdarzenia | Silnik | Poziom |
|---|---|---|
| `TCP_XMAS_SCAN` | Pakietowy | medium |
| `TCP_NULL_SCAN` | Pakietowy | medium |
| `TCP_SYN_FIN_ANOMALY` | Pakietowy | medium |
| `ICMP_TUNNELING_SUSPECTED` | Pakietowy | high |
| `ARP_SPOOFING_DETECTED` | Pakietowy | critical |
| `SUSPICIOUS_CRITICAL_PORT_ACCESS` | Pakietowy | low |
| `VOLUMETRIC_DDOS_DETECTED` | Pakietowy | critical |
| `SYN_FLOOD_DETECTED` | Pakietowy | critical |
| `SYN_FLOOD_HIGH_VOLUME` | Pakietowy | high |
| `DISTRIBUTED_DENIAL_OF_SERVICE` | Pakietowy | critical |
| `RESOURCE_EXHAUSTION` | SNMP | critical |
| `RESOURCE_STARVATION` | SNMP | critical |
| `CONTROL_PLANE_EXHAUSTION` | SNMP | critical |
| `MEMORY_LEAK_SUSPECTED` | SNMP | high |
| `LINK_FLAPPING` | SNMP | low |
| `ANOMALOUS_OUTBOUND_TRAFFIC` | SNMP | high |
| `DATA_REFRESH_SIGNAL` | Wewnętrzny (system) | — sygnał techniczny, nie jest alertem bezpieczeństwa — informuje frontend o dostępności nowych danych |

(Reguła `STEALTH_PORT_SCAN` istnieje w kodzie modułu `SnmpAnalyzer.py`, lecz jest obecnie zakomentowana i nieaktywna — patrz opis modułu w rozdziale 5.7.2.1.)

### 6.4 Kolekcja `telegram_subscribers`

| Pole | Typ | Opis |
|---|---|---|
| `chat_id` | integer | Unikalny identyfikator czatu Telegram autoryzowanego subskrybenta powiadomień |

### 6.5 Kolekcja `packets` (pomocnicza, nieaktywna w głównym potoku)

Kolekcja, dla której warstwa dostępu do danych (`db_tools.py`) definiuje funkcje `store_packet()` i `display_packets()`, jednak żaden z aktywnych modułów silnika detekcji nie wywołuje obecnie zapisu surowych pakietów do bazy (analiza pakietów odbywa się "w locie", bez trwałego archiwizowania każdego przechwyconego pakietu — decyzja architektoniczna zapewne podyktowana ograniczeniem rozmiaru bazy przy dużym natężeniu ruchu).

---

## 7. Interfejs API (REST + SSE)

Poniższa tabela zbiorczo prezentuje wszystkie endpointy HTTP wystawiane przez aplikację. Wszystkie ścieżki chronione wymagają aktywnej, uwierzytelnionej sesji (ciasteczko), zgodnie z logiką opisaną w rozdziale o module `core/auth.py`.

| Metoda | Ścieżka | Blueprint | Autoryzacja | Opis |
|---|---|---|---|---|
| GET | `/` | frontend | wymagana (przekierowanie) | Zwraca główny dashboard SPA (`dashboard.html`) |
| GET | `/auth/login` | auth | publiczny | Zwraca stronę logowania |
| POST | `/auth/login` | auth | publiczny | Weryfikuje hasło, tworzy sesję |
| POST | `/auth/logout` | auth | publiczny | Czyści sesję, kasuje ciasteczko |
| GET | `/auth/whoami` | auth | publiczny | Zwraca stan uwierzytelnienia bieżącej sesji |
| GET | `/devices` | devices | wymagana | Lista urządzeń (bez switchy) wraz ze statusem, danymi ogólnymi, interfejsami, wydajnością |
| GET | `/metrics` | metrics | wymagana | Historyczne serie czasowe metryk (CPU, RAM, ruch RX/TX) pogrupowane per urządzenie |
| GET | `/logs` | logs | wymagana | Pełna historia alertów bezpieczeństwa |
| GET | `/events` | events | wymagana | Strumień zdarzeń w czasie rzeczywistym (Server-Sent Events) |

Wszystkie odpowiedzi API zwracane są w formacie JSON (z wyjątkiem `/events`, zwracającym strumień typu `text/event-stream`), a serwer wymusza komunikację po protokole HTTPS (TLS) na porcie 8000.

---

## 8. Bezpieczeństwo systemu

Poniżej zebrano w jednym miejscu wszystkie obserwacje dotyczące warstwy bezpieczeństwa samej aplikacji NetPulse. Jako że projekt ma charakter w pełni jawny i open source, świadomość poniższych punktów jest szczególnie istotna przed wdrożeniem w środowisku produkcyjnym lub udostępnieniem repozytorium publicznie.

### 8.1 Mechanizm wczytywania konfiguracji

Plik `config.py` wykorzystuje mechanizm ładowania zmiennych środowiskowych za pomocą funkcji `load_dotenv()`, wskazując dedykowany plik konfiguracyjny zawierający wymagane parametry środowiskowe aplikacji. Podejście to pozwala na oddzielenie konfiguracji systemu od kodu źródłowego oraz umożliwia przechowywanie wartości konfiguracyjnych w jednym, centralnym miejscu.

W repozytorium znajduje się przykładowy plik konfiguracyjny `.env.example`, który definiuje strukturę wymaganych zmiennych środowiskowych oraz przykładowe wartości wykorzystywane podczas konfiguracji środowiska uruchomieniowego. Zawiera on między innymi parametry uwierzytelniania, takie jak `AUTH_PASSWORD` oraz `TELEGRAM_BOT_PASSWORD`, wykorzystywane przez odpowiednie komponenty systemu.

### 8.2 Mechanizm uwierzytelniania

System wykorzystuje jeden, wspólny dla wszystkich administratorów sekret dostępowy (pojedyncze hasło, odczytywane ze zmiennej środowiskowej `AUTH_PASSWORD`), bez rozróżnienia na indywidualne konta użytkowników, role czy poziomy uprawnień. Sesja realizowana jest w oparciu o standardowy, podpisywany kryptograficznie mechanizm sesji Flask.

### 8.3 Zarządzanie sekretami aplikacji

Klucz sesyjny Flask (`SECRET_KEY`), hasło logowania administratora (`AUTH_PASSWORD`), hasło subskrypcji Telegram (`TELEGRAM_BOT_PASSWORD`) oraz token API bota Telegram (`TELEGRAM_BOT_TOKEN`) są odczytywane wyłącznie ze zmiennych środowiskowych.

### 8.4 Domyślne społeczności SNMP

Klient SNMP (`AsyncSNMPPoller`) domyślnie próbuje uwierzytelnić się względem monitorowanych urządzeń przy użyciu listy powszechnie znanych, domyślnych społeczności (community strings): `public`, `cisco`, `admin`. Jest to zachowanie w pełni uzasadnione z punktu widzenia funkcjonalności monitoringu (SNMP w wersji 1/2c z definicji nie oferuje silniejszego uwierzytelniania), jednak stanowi jednocześnie przypomnienie, że skuteczność i bezpieczeństwo całego systemu monitoringu SNMP zależy od higieny konfiguracyjnej monitorowanej infrastruktury — w przyszłości planowana jest zmiana domyślnych community strings na urządzeniach sieciowych oraz, docelowo, migracja do SNMPv3 z pełnym uwierzytelnianiem i szyfrowaniem transportu.

### 8.5 Certyfikat TLS

Dołączona para certyfikat/klucz (`certs/cert.pem`, `certs/key.pem`) ma charakter deweloperski (self-signed, `CN=localhost`).

---

## 9. Instalacja i uruchomienie

Poniższa procedura odtwarza sposób uruchomienia aplikacji.

### 9.1 Krok 1 — przygotowanie środowiska

```bash
# Zalecany Python 3.11 lub starszy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 9.2 Krok 2 — konfiguracja zmiennych środowiskowych

```bash
cp .env.example .env
# Następnie edytuj plik .env i ustaw unikalne wartości dla:
#   SECRET_KEY, AUTH_PASSWORD, TELEGRAM_BOT_TOKEN, TELEGRAM_BOT_PASSWORD, MONGO_URI
# Należy również usunąć argument z wywołania funkcji `load_dotenv()`, aby domyślnie wczytywała konfigurację z pliku `.env`.
```

Wartość `TELEGRAM_BOT_TOKEN` należy pobrać podczas tworzenia nowego bota w serwisie Telegram. Token jest generowany przez narzędzie administracyjne BotFather i stanowi unikalny identyfikator umożliwiający aplikacji komunikację z Telegram Bot API. Otrzymany token należy następnie umieścić w odpowiednim polu konfiguracji środowiskowej `TELEGRAM_BOT_TOKEN`.

### 9.3 Krok 3 — uruchomienie bazy danych

Wymagana jest działająca lokalnie instancja MongoDB nasłuchująca na domyślnym porcie:

```bash
mongod --dbpath /sciezka/do/danych
```

### 9.4 Krok 4 — konfiguracja interfejsów sieciowych

Należy przygotować interfejs monitorujący (port mirroring/SPAN), na który przełącznik/router kopiuje kopię całego ruchu sieciowego przeznaczonego do analizy, oraz interfejs z dostępem do sieci zarządzającej urządzeniami przez SNMP.

### 9.5 Krok 5 — dostosowanie ścieżek i adresów specyficznych dla środowiska

Przed uruchomieniem w innym środowisku niż referencyjne, należy zaktualizować:

- ścieżkę do pliku `devices.json` w `workers/main.py` (obecnie zapisana na stałe jako bezwzględna ścieżka `/home/AdminNetPulse/NetPulseApp/workers/devices.json`),
- adres `API_BASE` w plikach `static/dashboard.html` oraz `static/login.html` (obecnie `https://172.16.253.1:8000`), tak aby wskazywał na rzeczywisty adres IP/nazwę hosta, pod którym uruchamiany jest backend,
- certyfikat TLS w katalogu `certs/` — dołączony certyfikat deweloperski ma ograniczony okres ważnośc i przed wdrożeniem powinien zostać wygenerowany na nowo lub zastąpiony certyfikatem z zaufanego CA.

### 9.6 Krok 6 — uruchomienie aplikacji

Aplikacja musi zostać uruchomiona z uprawnieniami administratora ze względu na wymogi przechwytywania pakietów na poziomie systemu operacyjnego:

```bash
sudo python3 app.py
```

Po starcie aplikacja zapyta interaktywnie o nazwy interfejsów sieciowych do wykorzystania (SNMP oraz port mirroringu), a następnie uruchomi serwer HTTPS na porcie 8000. Panel logowania dostępny będzie pod adresem `https://<adres_serwera>:8000/`.

---

## 10. Znane ograniczenia i rekomendowane kierunki rozwoju

Poniższa lista podsumowuje obserwacje wynikające z analizy kodu, które mogą stanowić punkt wyjścia do dalszego rozwoju projektu:

1. **Przeterminowany certyfikat TLS deweloperski** — certyfikat w `certs/cert.pem` posiada ograniczone, już zakończone okno ważności i wymaga wygenerowania nowego przed uruchomieniem serwera HTTPS.
2. **Ograniczony zakres detekcji wydajnościowej per producent** — tabela OID-ów wydajnościowych w `SnmpPoller.py` zawiera realne wpisy wyłącznie dla platform `Cisco IOS/Nexus` i `Linux/Unix Server`. Urządzenia MikroTik, Windows Server, Huawei i Juniper są rozpoznawane na etapie discovery, lecz na ten moment nie są objęte regułami detekcji anomalii CPU/RAM.
3. **Wyłączona reguła detekcji Stealth Port Scan** — gotowa, lecz zakomentowana logika w `SnmpAnalyzer.py`, oczekująca na dopracowanie progów przed ponownym włączeniem.
4. **Twarde kodowanie adresów i ścieżek specyficznych dla środowiska** — bezwzględna ścieżka do `devices.json` w `workers/main.py` oraz adres `API_BASE` w plikach frontendowych wymagają ręcznej edycji przy każdym nowym wdrożeniu; docelowo powinny pochodzić z konfiguracji zewnętrznej (zmienne środowiskowe / plik `.env`).
5. **Pojedyncze konto administracyjne** — brak systemu wielu użytkowników/ról; w miarę wzrostu zespołu operacyjnego korzystającego z systemu warto rozważyć pełny model kont z indywidualnym uwierzytelnianiem oraz mechanizm rate limitingu na endpointzie logowania.
6. **SNMP wyłącznie w wersji 1/2c** — obecna implementacja `SnmpPoller.py` opiera się na `CommunityData` (community strings), bez wsparcia dla SNMPv3 (uwierzytelnianie + szyfrowanie), co ogranicza poziom bezpieczeństwa samej warstwy monitoringu w sieciach o podwyższonych wymaganiach.
7. **Skalowalność pojedynczego procesu** — cała logika monitoringu (sniffing, polling SNMP, analiza, API webowe) działa w ramach jednego procesu Pythona kooperującego poprzez wątki/kolejki/asyncio; przy bardzo dużej liczbie monitorowanych urządzeń lub bardzo wysokim natężeniu ruchu na porcie mirroringu warto rozważyć rozdzielenie tych odpowiedzialności na niezależne procesy/usługi (np. komunikujące się poprzez kolejkę komunikatów typu Redis/RabbitMQ zamiast kolejek wewnątrzprocesowych).

---

## 11. Podsumowanie

NetPulse jest kompletnym, w pełni funkcjonalnym systemem klasy IDS, łączącym w spójnej, otwartoźródłowej architekturze dwie komplementarne metody detekcji zagrożeń sieciowych — analizę pakietów w czasie rzeczywistym (inspirowaną filozofią systemów takich jak Arbor Networks) oraz monitoring telemetryczny urządzeń poprzez SNMP (inspirowany podejściem systemów klasy Zabbix). System obejmuje pełny łańcuch przetwarzania danych: od odkrywania urządzeń w sieci, przez identyfikację i klasyfikację ich typu, cykliczne zbieranie telemetrii i pasywne przechwytywanie ruchu, poprzez wielowarstwowe reguły detekcji anomalii (sygnaturowe, statystyczne i różnicowe), aż po trwałą persystencję w MongoDB oraz wielokanałową dystrybucję alertów — do przeglądarki administratora w czasie rzeczywistym poprzez Server-Sent Events oraz do komunikatora Telegram.

Projekt w obecnej formie stanowi solidny fundament funkcjonalny, z jasno zidentyfikowanymi w niniejszej dokumentacji obszarami do dalszego dopracowania przed pełnym wdrożeniem produkcyjnym — w szczególności w zakresie poprawnego wczytywania konfiguracji środowiskowej, aktualności certyfikatu TLS, stabilności reguły detekcji rozproszonego DDoS, parametryzacji środowiskowej ścieżek i adresów oraz uporządkowania artefaktów pozostałych po wcześniejszych etapach rozwoju kodu.