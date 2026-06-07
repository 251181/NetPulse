from db_tools import store_packet, store_router, store_host, clear_database

if __name__ == "__main__":
    router = {
        "ip_address": "sum_address",
        "something": "something"
    }

    store_router(router)
