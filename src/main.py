import asyncio
import ping
import toml
from rich.live import Live
from rich.table import Table
from rich.console import Console

from rich.panel import Panel  # 追加
from rich.text import Text  # 追加
from rich.columns import Columns  # または Group を使う

# from rich.layout import Layout  # レイアウトをより細かく制御したい場合
from rich.align import Align  # テキストのアライメントを制御したい場合
from rich.box import ROUNDED  # Panelの枠線のスタイル

# 変数周り
RTT_SCALE = 10
# richのコンソールを初期化
console = Console()

toml_path = "./__targetfiles__/target.toml"
toml_data = toml.load(toml_path)


monitor_table = {
    data["name"]: {
        "hostname": data["name"],
        "address": data["ip"],
        "loss": str(0),
        "ttl": str(0),
        "type": str("0"),
        "rtt": str(0),
        "result": [" "] * 20,  # 初期化
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
    table.add_column("LOSS_PACKET", justify="right", style="cyan")
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
        # type の説明文を定義
    type_description = Text.from_markup(
        "Type Code Meanings:\n"
        "[blue]0[/blue]: Echo Reply (Success)\n"
        "[red]3[/red]: Destination Unreachable\n"
        "[red]4[/red]: Source Quench\n"
        "[red]5[/red]: Redirect\n"
        "[red]8[/red]: Echo Request\n"  # 本来表示されないはずだが参考として
        "[red]11[/red]: Time Exceeded (TTL expired)\n"
        "[red]12[/red]: Parameter Problem\n"
        "[yellow]TIMEOUT[/yellow]: Ping timed out (no response within threshold)"
    )

    # 説明文を Panel で囲む
    description_panel = Panel(
        Align.center(type_description, vertical="middle"),  # 中央揃えに
        title="[bold yellow]Type Codes Explanation[/bold yellow]",
        border_style="dim white",  # 枠線の色
        box=ROUNDED,  # 丸みを帯びた枠線
        padding=(1, 2),  # 内側のパディング
    )

    return Columns([table, description_panel], align="center")


def worker_ping(host, seq, id):
    """
    個別のスレッドでpingを実行し、結果を辞書として返すワーカー関数。
    """
    try:
        ip_header, echo_reply, rtt = ping.ping(host["ip"], seq, id)
        if ip_header is None and echo_reply is None and rtt is None:
            return {"name": host["name"], "status": "failure"}
        return {
            "name": host["name"],
            "status": "success",
            "rtt": int(rtt),
            "ttl": ip_header.ttl,
            "type": echo_reply.type.value,
        }
    except Exception as e:
        # ここに到達した場合、worker_ping内で例外が発生したことを意味する
        print(
            f"DEBUG: {host['name']} - worker_pingで例外が発生しました: {e}。status: 'failure'を返します。"
        )
        return {"name": host["name"], "status": "failure"}


async def producer(queue, host, id, sleep_interval):
    """Producer: 定期的にpingを実行し、結果をキューに入れる"""
    seq = 0
    while True:
        seq += 1
        try:
            # 同期的なping関数を別スレッドで実行
            result = await asyncio.wait_for(
                asyncio.to_thread(worker_ping, host, seq, id), timeout=4
            )
            await queue.put(result)
        except Exception:
            res = {"name": host["name"], "status": "failure"}
            await queue.put(res)

        # 次のサイクルまで待機
        await asyncio.sleep(sleep_interval)


async def consumer(queue, live):
    """Consumer: キューから結果を受け取り、テーブルを更新する"""
    while True:
        result = await queue.get()

        host_name = result["name"]
        if result["status"] == "success":
            rtt = result["rtt"]
            monitor_table[host_name]["rtt"] = str(rtt)
            monitor_table[host_name]["ttl"] = str(result["ttl"])
            monitor_table[host_name]["result"].append(visualize_rtt(rtt))
            monitor_table[host_name]["type"] = str(result["type"])
        elif result["status"] == "failure":
            print(
                f"DEBUG: {host_name} - 'failure'ステータスを処理中（TIMEOUTとして）"
            )  # 追加
            tmp: int = int(monitor_table[host_name]["loss"])
            monitor_table[host_name]["loss"] = str(tmp + 1)

            monitor_table[host_name]["type"] = "TIMEOUT"
            monitor_table[host_name]["result"].append("[red]✗[/red]")

        monitor_table[host_name]["result"] = monitor_table[host_name]["result"][-20:]

        # UIの更新はこのConsumerタスクが一元管理する
        live.update(generate_table(monitor_table))
        queue.task_done()


async def main(sleep_interval: int = 1):
    queue = asyncio.Queue()

    with Live(generate_table(monitor_table), refresh_per_second=4, screen=True) as live:
        # UIを更新する単一のConsumerタスクを生成
        consumer_task = asyncio.create_task(consumer(queue, live))

        # 各ホストのpingを実行するProducerタスクを生成
        producer_tasks = [
            asyncio.create_task(producer(queue, host, id, sleep_interval))
            for id, host in enumerate(toml_data["targets"])
        ]

        all_tasks = producer_tasks + [consumer_task]
        try:
            await asyncio.gather(*all_tasks)
        except KeyboardInterrupt:
            console.print("Exiting...")
        finally:
            # 終了時にすべてのタスクを安全にキャンセル
            for task in all_tasks:
                task.cancel()
            await asyncio.gather(*all_tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main(sleep_interval=1))

    except KeyboardInterrupt:
        # asyncio.runがKeyboardInterruptをハンドルするため、ここは通常不要だが念のため
        console.print("Exiting...")

    # queue = asyncio.Queue()
    # while True:
    #     res = worker_ping({"name": "test", "ip": "192.168.1.1"}, 1, 1)
    #     print(res)
