from db_tools import display_packets, display_devices, display_logs, display_metrics, display_subscribers, clear_database


def menu():
    menu_options = {
        "1": display_packets,
        "2": display_devices,
        "3": display_logs,
        "4": display_metrics,
        "5": display_subscribers,
        "6": clear_database
    }

    menu_entry_text = "1. DISPLAY ALL PACKETS\n" \
                      "2. DISPLAY ALL DEVICES\n" \
                      "3. DISPLAY ALL LOGS\n" \
                      "4. DISPLAY ALL METRICS\n" \
                      "5. DISPLAY ALL SUBSCRIBERS\n" \
                      "6. CLEAR DATABASE\n" \
                      "> "

    user_input = input(menu_entry_text)

    action = menu_options.get(user_input)

    if action:
        action()
    else:
        print("Invalid option. Please choose 1-3.")


if __name__ == "__main__":
    menu()
