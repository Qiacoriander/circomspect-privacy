import os
import time
import requests
import subprocess
import shutil

# 使用说明：
# 1. 在运行前，建议申请一个 GitHub Personal Access Token (PAT) 并设置为环境变量 GITHUB_TOKEN
#    如果没有 Token，也可以运行，但极易触发 GitHub API rate limit (每小时 60 次)。
# 2. 运行此脚本，它会在同级的 `evaluation_projects` 文件夹中，下载包含目标电路的整个 GitHub 仓库。

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

# 搜索符合我们要求的 Circom 代码
# 关键字: component main public 并且扩展名为 circom
SEARCH_QUERY = "extension:circom component main public"
SEARCH_URL = f"https://api.github.com/search/code?q={SEARCH_QUERY}&sort=indexed"

from pathlib import Path
OUTPUT_DIR = str(Path(__file__).resolve().parent.parent / "evaluation_projects")

# 需要跳过的仓库黑名单 
BLACKLIST = {
    "rarimo/passport-zk-circuits",
    "andyguzmaneth/zkwebauthn-webauthn-circom",
    "ArmanKolozyan/CCC-Check",
    "jinan789/ScaleCirc",
    "distributed/lab_circom-g4-grammar",
    "doutv/circom-benchmark",
    "htried/zkp-ldp",
    "dangduongminhnhat/Circheck",
    "doutv/circom-benchmark",
    "dl-solarity/circom-lib",
    "Veridise/circom-benchmarks",
    "Kiligram/permissionless-zkBridge",
    "whbjzzwjxq/ZKAP",
    "whbjzzwjxq/ZKAP-bmk-telepathy",
    "flyinglimao/zkenc-benchmark",
    "TusimaNetwork/circom-pairing",
    "ChainSafe/recursive-zk-bridge",
    "yi-sun/circom-pairing",
    "Oraisan/Oraisan-Circuit-Demo",
    "chyanju/Picus",
    "TusimaNetwork/circom-pairing",
    "xBalbinus/circomference",
    "ouromoros/zk-hackathon"
}

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    # 限制下载的单个仓库最大大小为 300 MB (300000 KB)
    MAX_REPO_SIZE_KB = 300000
    
    # 建立多页请求逻辑保证抓取足够多的项目
    page = 1
    count = 0
    downloaded_repos = set()
    
    print(f"[*] 我们将尝试分页克隆前 500 个不重复且大小小于 {MAX_REPO_SIZE_KB/1024:.0f}MB 的完整项目作为评估样本。")

    while count < 500:
        paginated_url = f"{SEARCH_URL}&per_page=100&page={page}"
        print(f"[*] 正在请求第 {page} 页数据...")
        response = requests.get(paginated_url, headers=HEADERS)
        
        if response.status_code != 200:
            print(f"[!] 搜索失败！状态码: {response.status_code}")
            if response.status_code == 403 or response.status_code == 401:
                print("[!] 可能是触发了 Rate Limit 或者 Token 无效。请设置 GITHUB_TOKEN 环境变量后再试。")
            break

        data = response.json()
        items = data.get("items", [])
        
        if not items:
            print("已经没有更多搜索结果了，拉取中止。")
            break
    
        for item in items:
            if count >= 500:
                break
            
            repo_full_name = item["repository"]["full_name"]
            if repo_full_name in downloaded_repos or repo_full_name in BLACKLIST:
                if repo_full_name in BLACKLIST:
                    print(f"    -> 🚫 跳过黑名单项目 {repo_full_name}")
                continue
                
            # 请求仓库详情以获取大小信息
            repo_url = item["repository"]["url"]
            try:
                repo_resp = requests.get(repo_url, headers=HEADERS, timeout=10)
                if repo_resp.status_code == 200:
                    repo_info = repo_resp.json()
                    # GitHub API 返回的 size 单位通常是 KB
                    repo_size_kb = repo_info.get("size", 0)
                    if repo_size_kb > MAX_REPO_SIZE_KB:
                        print(f"    -> ⚠️ 跳过过大项目 {repo_full_name} (项目大小: {repo_size_kb/1024:.2f} MB)")
                        continue
                else:
                    print(f"    -> ⚠️ 无法获取项目 {repo_full_name} 的详细信息，跳过。")
                    continue
            except requests.exceptions.RequestException as e:
                print(f"    -> ⚠️ 请求项目 {repo_full_name} 详细信息时发生网络错误: {e}，跳过。")
                continue
                
            repo_name_safe = repo_full_name.replace("/", "_")
            clone_url = item["repository"]["html_url"] + ".git"
            
            print(f"    -> 正在克隆项目 {repo_full_name} (项目大小: {repo_size_kb/1024:.2f} MB)...")
            
            save_path = os.path.join(OUTPUT_DIR, repo_name_safe)
            if os.path.exists(save_path) and os.path.isdir(save_path):
                print(f"       ⚠️ 目录已存在: {save_path}，跳过克隆。")
                downloaded_repos.add(repo_full_name)
                # 不增加 count，以确保本次运行能够真正拉取到 500 个新项目
                continue
                
            try:
                # 使用 git clone 下载整个仓库，--depth 1 可以加快克隆速度并节省空间
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", clone_url, save_path], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    print(f"       ✅ 克隆成功: {save_path}")
                    downloaded_repos.add(repo_full_name)
                    count += 1
                else:
                    print(f"       ❌ 克隆失败: {result.stderr}")
            except Exception as e:
                print(f"       ❌ 执行 git clone 出错: {e}")
                
            # 增加延迟以防止过快请求
            time.sleep(1)
        
        # 每页结束翻页
        page += 1
        time.sleep(2)
        
    print(f"[*] 下载结束。完整的测试项目已存储在 {OUTPUT_DIR} 文件夹下。您可以使用 circomspect 对它们进行测试。")

if __name__ == "__main__":
    main()
