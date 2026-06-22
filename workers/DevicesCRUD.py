import json
import os

FILE_NAME = "devices.json"


def load_devices():
    if os.path.exists(FILE_NAME) and os.path.getsize(FILE_NAME) > 0:
        with open(FILE_NAME, "r", encoding="utf-8") as file:
            return json.load(file)
    return {}


def save_devices(devices):
    with open(FILE_NAME, "w", encoding="utf-8") as file:
        json.dump(devices, file, indent=2, ensure_ascii=False)


def format_key(key):
    key = key.strip()
    if key and not key.startswith("("):
        key = f"({key})"
    return key


def show_devices(devices):
    print("\n=== AKTUALNA LISTA URZĄDZEŃ ===")
    if not devices:
        print("[Baza jest pusta]")
        return False
    
    # Formatujemy wyświetlanie w ładną tabelkę
    for image, dev_type in devices.items():
        print(f"  {image:<30} -> {dev_type}")
    print("===============================")
    return True


def add_or_update_device(devices):
    print("\n--- Dodawanie / Modyfikacja pozycji ---")
    image_name = input("Podaj nazwę obrazu (np. C3640-A3JS-M): ")
    image_name = format_key(image_name)

    if not image_name or image_name == "()":
        print("Błąd: Nazwa obrazu nie może być pusta!")
        return

    if image_name in devices:
        print(f"Modyfikujesz istniejący obraz. Obecny typ: '{devices[image_name]}'")
    
    device_type = input("Podaj typ urządzenia (np. Switch, Router): ").strip()

    if not device_type:
        print("Błąd: Typ urządzenia nie może być pusty!")
        return

    devices[image_name] = device_type
    save_devices(devices)
    print(f"Pomyślnie zapisano: {image_name} -> {device_type}")


def delete_device(devices):
    print("\n--- Usuwanie pozycji ---")
    if not show_devices(devices):
        return

    image_name = input("\nPodaj pełną nazwę obrazu do usunięcia: ")
    image_name = format_key(image_name)

    if image_name in devices:
        potwierdzenie = input(f"Czy na pewno chcesz usunąć {image_name}? (t/N): ").strip().lower() or 'n'
        if potwierdzenie == 't':
            del devices[image_name]
            save_devices(devices)
            print(f"Pozycja {image_name} została usunięta.")
        else:
            print("Anulowano usuwanie.")
    else:
        print(f"Błąd: Nie znaleziono obrazu '{image_name}' w bazie.")


def main():
    while True:
        devices = load_devices()

        print("\n=== MENU ZARZĄDZANIA OBRAZAMI ===")
        print("1. Wyświetl wszystkie urządzenia")
        print("2. Dodaj / Modyfikuj urządzenie")
        print("3. Usuń urządzenie")
        print("4. Wyjście")
        
        wybor = input("Wybierz opcję (1-4): ").strip()

        if wybor == "1":
            show_devices(devices)
        elif wybor == "2":
            add_or_update_device(devices)
        elif wybor == "3":
            delete_device(devices)
        elif wybor == "4":
            print("Zamykanie programu. Do zobaczenia!")
            break
        else:
            print("Niepoprawny wybór, spróbuj ponownie.")
        
        input("\nNaciśnij Enter, aby wrócić do menu...")


if __name__ == "__main__":
    main()