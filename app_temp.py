import threading

from workers.main import main

if __name__ == "__main__":    
    t = threading.Thread(target=main, daemon=True)
    t.start()
    t.join()
