import time
import ping
import toml


toml_path = "./target.toml"
toml_data = toml.load(toml_path)

for host in toml_data["targets"]:
    print(f"hostname: {host["name"]}")
    while True:

        _, _, res = ping.ping(host["ip"], 1, 1)
        print(f"ping: {res} ms")
        time.sleep(1)
