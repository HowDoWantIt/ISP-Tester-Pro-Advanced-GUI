import datetime

def log_to_file(message, filename="log.txt"):
    with open(filename, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def log_console(message):
    print(message)
