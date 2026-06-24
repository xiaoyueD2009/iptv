#!/usr/bin/env python3
"""
IPTV 源健康检测工具
- 并发检测源存活状态
- 按响应速度排序
- 标记运营商（移动/联通/电信/广电/公网）
- 去重（同一频道保留最快源）
- 输出干净的 txt 和 m3u 文件
"""

import os
import re
import sys
import time
import socket
import struct
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


ISP_IP_RANGES = {
    "移动": [
        ("112.0.0.0", "112.63.255.255"),
        ("117.0.0.0", "117.63.255.255"),
        ("183.192.0.0", "183.255.255.255"),
        ("36.0.0.0", "36.127.255.255"),
        ("39.0.0.0", "39.127.255.255"),
        ("111.0.0.0", "111.63.255.255"),
        ("120.0.0.0", "120.63.255.255"),
        ("122.0.0.0", "122.63.255.255"),
        ("223.0.0.0", "223.255.255.255"),
    ],
    "联通": [
        ("123.128.0.0", "123.191.255.255"),
        ("125.32.0.0", "125.63.255.255"),
        ("221.192.0.0", "221.223.255.255"),
        ("60.0.0.0", "60.31.255.255"),
        ("61.136.0.0", "61.191.255.255"),
        ("58.16.0.0", "58.31.255.255"),
        ("119.16.0.0", "119.23.255.255"),
        ("220.192.0.0", "220.223.255.255"),
    ],
    "电信": [
        ("114.64.0.0", "114.127.255.255"),
        ("180.96.0.0", "180.127.255.255"),
        ("218.0.0.0", "218.31.255.255"),
        ("59.32.0.0", "59.63.255.255"),
        ("222.160.0.0", "222.191.255.255"),
        ("182.112.0.0", "182.191.255.255"),
        ("61.128.0.0", "61.191.255.255"),
        ("123.128.0.0", "123.191.255.255"),
    ],
    "广电": [
        ("172.16.0.0", "172.31.255.255"),
        ("10.0.0.0", "10.255.255.255"),
        ("100.64.0.0", "100.127.255.255"),
    ],
}


def ip_to_int(ip_str):
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except Exception:
        return 0


def detect_isp(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return "未知"
        ip_str = socket.gethostbyname(host)
        ip_int = ip_to_int(ip_str)

        for isp, ranges in ISP_IP_RANGES.items():
            for start, end in ranges:
                if ip_to_int(start) <= ip_int <= ip_to_int(end):
                    return isp

        if ip_str.startswith("10.") or ip_str.startswith("192.168."):
            return "内网"

        return "公网"
    except Exception:
        return "未知"


def check_source(url, timeout=5):
    start_time = time.time()
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result != 0:
            return None

        if HAS_REQUESTS:
            resp = requests.head(url, timeout=timeout, allow_redirects=True)
            if resp.status_code >= 400:
                resp = requests.get(url, timeout=timeout, stream=True)
                resp.close()
                if resp.status_code >= 400:
                    return None
        else:
            req = urllib.request.Request(url, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=timeout)
            if resp.status >= 400:
                return None

        elapsed = (time.time() - start_time) * 1000
        return round(elapsed, 1)
    except Exception:
        return None


def check_source_m3u8(url, timeout=8):
    start_time = time.time()
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result != 0:
            return None

        elapsed = (time.time() - start_time) * 1000
        return round(elapsed, 1)
    except Exception:
        return None


def parse_txt(filepath):
    channels = defaultdict(list)
    current_group = "未分组"

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.endswith("#genre#"):
                current_group = line.replace(",#genre#", "").replace("#genre#", "").strip()
                continue
            if "," in line:
                parts = line.split(",", 1)
                name = parts[0].strip()
                url = parts[1].strip()
                if url.startswith("http"):
                    channels[current_group].append((name, url))

    return channels


def parse_m3u(filepath):
    channels = defaultdict(list)
    current_group = "未分组"
    current_name = None

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line == "#EXTM3U":
            continue
        if line.startswith("#EXTINF:"):
            if "group-title=" in line:
                group_match = re.search(r'group-title="([^"]*)"', line)
                current_group = group_match.group(1) if group_match else "未分组"
            current_name = line.split(",")[-1].strip()
        elif line.startswith("http") and current_name:
            channels[current_group].append((current_name, line))
            current_name = None

    return channels


def check_all_sources(channels, max_workers=30, timeout=5):
    all_items = []
    for group, items in channels.items():
        for name, url in items:
            all_items.append((group, name, url))

    results = []
    total = len(all_items)
    done = 0

    print(f"开始检测 {total} 个源（并发数: {max_workers}）...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for group, name, url in all_items:
            if ".m3u8" in url:
                future = executor.submit(check_source_m3u8, url, timeout + 3)
            else:
                future = executor.submit(check_source, url, timeout)
            future_map[future] = (group, name, url)

        for future in as_completed(future_map):
            done += 1
            group, name, url = future_map[future]
            latency = future.result()
            if done % 50 == 0 or done == total:
                print(f"  进度: {done}/{total}")

            if latency is not None:
                isp = detect_isp(url)
                results.append((group, name, url, latency, isp))

    print(f"检测完成: {len(results)}/{total} 个源存活")
    return results


def dedup_and_sort(results):
    grouped = defaultdict(list)
    for group, name, url, latency, isp in results:
        grouped[(group, name)].append((url, latency, isp))

    deduped = []
    for (group, name), sources in grouped.items():
        sources.sort(key=lambda x: x[1])
        best = sources[0]
        deduped.append((group, name, best[0], best[1], best[2]))

    grouped_final = defaultdict(list)
    for group, name, url, latency, isp in deduped:
        grouped_final[group].append((name, url, latency, isp))

    for group in grouped_final:
        grouped_final[group].sort(key=lambda x: x[0])

    return grouped_final


def write_txt(grouped_results, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"更新时间,#genre#\n")
        f.write(f"{update_time},https://github.com/xiaoyueD2009/iptv\n\n")

        for group in sorted(grouped_results.keys()):
            items = grouped_results[group]
            f.write(f"{group},#genre#\n")
            for name, url, latency, isp in items:
                f.write(f"{name},{url}\n")
            f.write("\n")

    print(f"已写入: {filepath}")


def write_m3u(grouped_results, filepath, epg_url="http://epg.112114.xyz/pp.xml"):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f'#EXTM3U x-tvg-url="{epg_url}"\n')

        for group in sorted(grouped_results.keys()):
            items = grouped_results[group]
            for name, url, latency, isp in items:
                logo = f"https://tb.zbds.top/logo/{name}.png"
                f.write(f'#EXTINF:-1 group-title="{group}" tvg-name="{name}" tvg-logo="{logo}",{name}\n')
                f.write(f"{url}\n")

    print(f"已写入: {filepath}")


def main():
    parser = argparse.ArgumentParser(description="IPTV 源健康检测工具")
    parser.add_argument("input", nargs="+", help="输入文件路径（txt 或 m3u）")
    parser.add_argument("--workers", type=int, default=30, help="并发线程数 (默认: 30)")
    parser.add_argument("--timeout", type=int, default=5, help="超时秒数 (默认: 5)")
    parser.add_argument("--output-dir", default=None, help="输出目录 (默认: 输入文件所在目录)")
    parser.add_argument("--min-sources", type=int, default=1, help="每个频道最少保留源数 (默认: 1)")
    args = parser.parse_args()

    for input_file in args.input:
        if not os.path.exists(input_file):
            print(f"文件不存在: {input_file}")
            continue

        print(f"\n{'='*50}")
        print(f"处理文件: {input_file}")
        print(f"{'='*50}")

        ext = os.path.splitext(input_file)[1].lower()
        if ext == ".m3u":
            channels = parse_m3u(input_file)
        else:
            channels = parse_txt(input_file)

        total_channels = sum(len(v) for v in channels.values())
        print(f"读取到 {len(channels)} 个分组，{total_channels} 个频道条目")

        results = check_all_sources(channels, args.workers, args.timeout)
        grouped = dedup_and_sort(results)

        alive_channels = sum(len(v) for v in grouped.values())
        print(f"\n存活频道: {alive_channels} / {total_channels}")

        output_dir = args.output_dir or os.path.dirname(input_file) or "."
        base_name = os.path.splitext(os.path.basename(input_file))[0]

        txt_path = os.path.join(output_dir, f"{base_name}.txt")
        m3u_path = os.path.join(output_dir, f"{base_name}.m3u")

        write_txt(grouped, txt_path)
        write_m3u(grouped, m3u_path)

    print(f"\n{'='*50}")
    print("全部处理完成!")


if __name__ == "__main__":
    main()
