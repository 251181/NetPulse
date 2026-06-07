from db_tools import display_packets, display_routers, display_hosts, clear_database


def menu():
    menu_options = {
        "1": display_packets,
        "2": display_routers,
        "3": display_hosts,
        "4": clear_database
    }

    menu_entry_text = "1. DISPLAY ALL PACKETS\n" \
                      "2. DISPLAY ALL ROUTERS\n" \
                      "3. DISPLAY ALL HOSTS\n" \
                      "4. CLEAR DATABASE\n" \
                      "> "

    user_input = input(menu_entry_text)

    action = menu_options.get(user_input)

    if action:
        action()
    else:
        print("Invalid option. Please choose 1-3.")


if __name__ == "__main__":
    menu()
