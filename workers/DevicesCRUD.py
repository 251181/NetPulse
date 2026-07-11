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
    print("\n=== CURRENT DEVICE LIST ===")
    if not devices:
        print("[Database is empty]")
        return False
    
    # Formatujemy wyświetlanie w ładną tabelkę
    for image, dev_type in devices.items():
        print(f"  {image:<30} -> {dev_type}")
    print("===============================")
    return True


def add_or_update_device(devices):
    print("\n--- Adding / Updating Device ---")
    image_name = input("Enter device image name (e.g., C3640-A3JS-M): ")
    image_name = format_key(image_name)

    if not image_name or image_name == "()":
        print("Error: Device image name cannot be empty!")
        return

    if image_name in devices:
        print(f"Updating existing image. Current type: '{devices[image_name]}'")
    
    device_type = input("Enter device type (e.g., Switch, Router): ").strip()

    if not device_type:
        print("Error: Device type cannot be empty!")
        return

    devices[image_name] = device_type
    save_devices(devices)
    print(f"Successfully saved: {image_name} -> {device_type}")


def delete_device(devices):
    print("\n--- Deleting Device ---")
    if not show_devices(devices):
        return

    image_name = input("\nEnter full device image name to delete: ")
    image_name = format_key(image_name)

    if image_name in devices:
        confirmation = input(f"Are you sure you want to delete {image_name}? (t/N): ").strip().lower() or 'n'
        if confirmation == 't':
            del devices[image_name]
            save_devices(devices)
            print(f"Position {image_name} has been deleted.")
        else:
            print("Deletion cancelled.")
    else:
        print(f"Error: Device image '{image_name}' not found in the database.")


def main():
    while True:
        devices = load_devices()

        print("\n=== ISO MANAGMENT MENU ===")
        print("1. Display all devices")
        print("2. Add / Modify device")
        print("3. Delete device")
        print("4. Exit")
        
        wybor = input("Choose an option (1-4): ").strip()

        if wybor == "1":
            show_devices(devices)
        elif wybor == "2":
            add_or_update_device(devices)
        elif wybor == "3":
            delete_device(devices)
        elif wybor == "4":
            print("Closing program. See you!")
            break
        else:
            print("Invalid choice, please try again.")
        
        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()