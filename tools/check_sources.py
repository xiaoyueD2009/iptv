#!/usr/bin/env python3
"""
IPTV 源健康检测工具
- 并发检测源存活状态
- 按响应速度排序
- 标记运营商（移动/联通/电信/广电/公网）
- 国外源检测与标记（ip-api.com）
- 国内源优先排序
- 去重（同一频道保留最快 Top N 源）
- 输出干净的 txt 和 m3u 文件
"""

import os
import re
import sys
import time
import json
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


_country_cache = {}


def batch_detect_countries(hosts):
    unique_ips = {}
    for h in hosts:
        if h in _country_cache:
            continue
        try:
            ip = socket.gethostbyname(h)
            unique_ips[h] = ip
        except Exception:
            _country_cache[h] = ("未知", None)

    ip_to_hosts = defaultdict(list)
    for h, ip in unique_ips.items():
        ip_to_hosts[ip].append(h)

    unique_ip_list = list(ip_to_hosts.keys())

    for i in range(0, len(unique_ip_list), 100):
        batch = unique_ip_list[i:i + 100]
        try:
            if HAS_REQUESTS:
                resp = requests.post(
                    "http://ip-api.com/batch?fields=query,countryCode,country",
                    json=batch, timeout=10
                )
                results = resp.json()
            else:
                data = json.dumps(batch).encode()
                req = urllib.request.Request(
                    "http://ip-api.com/batch?fields=query,countryCode,country",
                    data=data,
                    headers={"Content-Type": "application/json"}
                )
                results = json.loads(urllib.request.urlopen(req, timeout=10).read())

            for r in results:
                ip = r.get("query", "")
                cc = r.get("countryCode", "")
                cn = r.get("country", "")
                for h in ip_to_hosts.get(ip, []):
                    _country_cache[h] = (cn or "未知", cc or "")
        except Exception as e:
            print(f"  国家检测批次失败: {e}")
            for ip in batch:
                for h in ip_to_hosts.get(ip, []):
                    _country_cache[h] = ("未知", "")
        if i + 100 < len(unique_ip_list):
            time.sleep(1.2)

    return {h: _country_cache.get(h, ("未知", "")) for h in hosts}


def is_domestic(country_code):
    return country_code in ("CN", "", None)


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


def strip_latency_tag(name):
    name = re.sub(r'\s*\[\d+ms(?:\|[^\]]+)?\]\s*', '', name)
    name = re.sub(r'\s*\[(?:移动|联通|电信|公网|广电|内网|未知)\]\s*', '', name)
    return name.strip()


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
                name = strip_latency_tag(parts[0].strip())
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
            current_name = strip_latency_tag(line.split(",")[-1].strip())
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

    all_hosts = set()
    for _, _, url, _, _ in results:
        host = urlparse(url).hostname
        if host:
            all_hosts.add(host)

    print(f"检测源所在国家（{len(all_hosts)} 个域名）...")
    country_map = batch_detect_countries(all_hosts)

    results_with_country = []
    foreign_count = 0
    for group, name, url, latency, isp in results:
        host = urlparse(url).hostname
        country_name, country_code = country_map.get(host, ("未知", ""))
        domestic = is_domestic(country_code)
        if not domestic:
            foreign_count += 1
        results_with_country.append((group, name, url, latency, isp, country_name, country_code, domestic))

    print(f"其中国内源: {len(results_with_country) - foreign_count}, 国外源: {foreign_count}")
    return results_with_country


def protocol_score(url):
    score = 0
    if url.startswith("https://"):
        score += 100
    if ".m3u8" in url:
        score += 50
    return score


def dedup_and_sort(results, top_n=3):
    grouped = defaultdict(list)
    for group, name, url, latency, isp, country_name, country_code, domestic in results:
        grouped[(group, name)].append((url, latency, isp, country_name, country_code, domestic))

    deduped = []
    for (group, name), sources in grouped.items():
        def sort_key(x):
            dom_bonus = 0 if x[5] else 5000
            return x[1] - protocol_score(x[0]) / 100 + dom_bonus

        sources.sort(key=sort_key)
        for url, latency, isp, cn, cc, dom in sources[:top_n]:
            deduped.append((group, name, url, latency, isp, cn, cc, dom))

    grouped_final = defaultdict(list)
    for group, name, url, latency, isp, cn, cc, dom in deduped:
        grouped_final[group].append((name, url, latency, isp, cn, cc, dom))

    for group in grouped_final:
        channels = defaultdict(list)
        for name, url, latency, isp, cn, cc, dom in grouped_final[group]:
            channels[name].append((url, latency, isp, cn, cc, dom))
        sorted_names = sorted(channels.keys(), key=lambda n: min(
            c[1] + (0 if c[5] else 5000) for c in channels[n]
        ))
        sorted_items = []
        for name in sorted_names:
            for url, latency, isp, cn, cc, dom in channels[name]:
                sorted_items.append((name, url, latency, isp, cn, cc, dom))
        grouped_final[group] = sorted_items

    return grouped_final


def format_tag(latency, isp, country_name, country_code, domestic):
    if domestic:
        if latency < 500:
            return f"[{int(latency)}ms|{isp}]"
        return f"[{isp}]"
    short = {"United States": "美", "Canada": "加", "Germany": "德",
             "South Korea": "韩", "France": "法", "Singapore": "新加坡",
             "United Kingdom": "英", "Taiwan": "台", "Japan": "日",
             "Hong Kong": "港", "Netherlands": "荷", "Russia": "俄",
             "British Virgin Islands": "BVI", "Australia": "澳",
             "India": "印", "Brazil": "巴", "Vietnam": "越",
             "Thailand": "泰", "Malaysia": "马来", "Indonesia": "印尼"}
    label = short.get(country_name, country_name[:4] if country_name else "外")
    return f"[{label}]"


def write_txt(grouped_results, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"更新时间,#genre#\n")
        f.write(f"{update_time},https://github.com/xiaoyueD2009/iptv\n\n")

        for group in sorted(grouped_results.keys()):
            items = grouped_results[group]
            f.write(f"{group},#genre#\n")
            for name, url, latency, isp, cn, cc, dom in items:
                tag = format_tag(latency, isp, cn, cc, dom)
                f.write(f"{name}{tag},{url}\n")
            f.write("\n")

    print(f"已写入: {filepath}")


def write_m3u(grouped_results, filepath, epg_url="http://epg.112114.xyz/pp.xml"):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f'#EXTM3U x-tvg-url="{epg_url}"\n')

        for group in sorted(grouped_results.keys()):
            items = grouped_results[group]
            for name, url, latency, isp, cn, cc, dom in items:
                logo = f"https://tb.zbds.top/logo/{name}.png"
                tag = format_tag(latency, isp, cn, cc, dom)
                display = f"{name}{tag}" if dom else f"{name}{tag}"
                if dom and latency < 500:
                    display = f"{name} [{int(latency)}ms]"
                f.write(f'#EXTINF:-1 group-title="{group}" tvg-name="{name}" tvg-logo="{logo}",{display}\n')
                f.write(f"{url}\n")

    print(f"已写入: {filepath}")


def main():
    parser = argparse.ArgumentParser(description="IPTV 源健康检测工具")
    parser.add_argument("input", nargs="+", help="输入文件路径（txt 或 m3u）")
    parser.add_argument("--workers", type=int, default=30, help="并发线程数 (默认: 30)")
    parser.add_argument("--timeout", type=int, default=5, help="超时秒数 (默认: 5)")
    parser.add_argument("--output-dir", default=None, help="输出目录 (默认: 输入文件所在目录)")
    parser.add_argument("--top-n", type=int, default=3, help="每个频道最多保留源数 (默认: 3)")
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
        grouped = dedup_and_sort(results, top_n=args.top_n)

        alive_channels = sum(len(v) for v in grouped.values())
        domestic_count = sum(1 for items in grouped.values() for _, _, _, _, _, _, dom in items if dom)
        foreign_count = alive_channels - domestic_count
        print(f"\n存活频道: {alive_channels} / {total_channels} (国内: {domestic_count}, 国外: {foreign_count})")

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
