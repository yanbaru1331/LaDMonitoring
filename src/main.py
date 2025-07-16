import time
import ping
import toml
from rich.live import Live
from rich.table import Table
from rich.console import Console

# 変数周り
RTT_SCALE = 10
# richのコンソールを初期化
console = Console()

toml_path = "./target.toml"
toml_data = toml.load(toml_path)


monitor_table = {
    data["name"]: {
        "hostname": data["name"],
        "address": data["ip"],
        "loss": str(0),
        "ttl": str(0),
        "type": str("0"),
        "rtt": str(0),
        "result": [""] * 20,  # 初期化
    }
    for data in toml_data["targets"]
}


def visualize_rtt(rtt: int):
    if rtt < RTT_SCALE * 1:
        return "▁"
    if rtt < RTT_SCALE * 2:
        return "▂"
    if rtt < RTT_SCALE * 3:
        return "▃"
    if rtt < RTT_SCALE * 4:
        return "▄"
    if rtt < RTT_SCALE * 5:
        return "▅"
    if rtt < RTT_SCALE * 6:
        return "▆"
    if rtt < RTT_SCALE * 7:
        return "▇"

    return "█"


def generate_table(monitor_data):

    table = Table(
        title="[bold green]Ping Monitor[/bold green]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("HOSTNAME", style="cyan", no_wrap=True)
    table.add_column("ADDRESS", style="cyan")
    table.add_column("LOSS", justify="right", style="cyan")
    table.add_column("TTL", justify="right", style="cyan")
    table.add_column("TYPE", style="cyan")
    table.add_column("RTT", justify="right", style="cyan")
    table.add_column("RESULT", style="cyan", justify="left")

    for host, data in monitor_data.items():
        table.add_row(
            data["hostname"],
            data["address"],
            data["loss"],
            data["ttl"],
            data["type"],
            data["rtt"],
            "".join(data["result"]),
        )
    return table


with Live(generate_table(monitor_table), refresh_per_second=1, screen=True) as live:
    try:
        while True:
            for host in toml_data["targets"]:
                try:
                    ip_header, echo_reply, rtt = ping.ping(host["ip"], 1, 1)
                    rtt = int(rtt)
                    monitor_table[host["name"]]["rtt"] = str(rtt)
                    monitor_table[host["name"]]["ttl"] = str(ip_header.ttl)
                    monitor_table[host["name"]]["result"].append(visualize_rtt(rtt))
                    monitor_table[host["name"]]["result"] = monitor_table[host["name"]][
                        "result"
                    ][
                        -20:
                    ]  # 最新20件のみ保持
                    monitor_table[host["name"]]["type"] = str(echo_reply.type.value)
                except Exception:
                    monitor_table[host["name"]]["result"] = "[red]✗[/red]"
                live.update(generate_table(monitor_table))
                time.sleep(1)  # 1秒待機
    except KeyboardInterrupt:
        console.print("exiting...")
# with Live(generate_table)
# for host in toml_data["targets"]:
#     print(f"hostname: {host["name"]}")
#     while True:
