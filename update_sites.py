import requests
import re
import json

mirror_pages = [
    {"name": "Hetzner Germany", "country": "DE", "url": "https://speed.hetzner.de/", "pattern": r'https://speed\.hetzner\.de/[0-9A-Za-z]+\.bin'},
    {"name": "ThinkBroadband UK", "country": "UK", "url": "http://ipv4.download.thinkbroadband.com/", "pattern": r'http://ipv4\.download\.thinkbroadband\.com/[0-9A-Za-z]+\.zip'},
    {"name": "OVH France", "country": "FR", "url": "http://proof.ovh.net/files/", "pattern": r'http://proof\.ovh\.net/files/[0-9A-Za-z]+\.(dat|zip)'},
    {"name": "Tele2 Sweden", "country": "SE", "url": "http://speedtest.tele2.net/", "pattern": r'http://speedtest\.tele2\.net/[0-9A-Za-z]+\.zip'},
    {"name": "Leaseweb NL", "country": "NL", "url": "https://mirror.nl.leaseweb.net/speedtest/", "pattern": r'https://mirror\.nl\.leaseweb\.net/speedtest/[0-9A-Za-z]+\.(bin|zip)'},
    {"name": "Leaseweb DE", "country": "DE", "url": "https://mirror.de.leaseweb.net/speedtest/", "pattern": r'https://mirror\.de\.leaseweb\.net/speedtest/[0-9A-Za-z]+\.(bin|zip)'},
    {"name": "Leaseweb US", "country": "US", "url": "https://mirror.us.leaseweb.net/speedtest/", "pattern": r'https://mirror\.us\.leaseweb\.net/speedtest/[0-9A-Za-z]+\.(bin|zip)'},
    {"name": "Leaseweb SG", "country": "SG", "url": "https://mirror.sg.leaseweb.net/speedtest/", "pattern": r'https://mirror\.sg\.leaseweb\.net/speedtest/[0-9A-Za-z]+\.(bin|zip)'},
    {"name": "Linode US", "country": "US", "url": "https://speedtest.newark.linode.com/", "pattern": r'https://speedtest\.newark\.linode\.com/[0-9A-Za-z\-]+\.bin'},
    {"name": "Linode DE", "country": "DE", "url": "https://speedtest.frankfurt.linode.com/", "pattern": r'https://speedtest\.frankfurt\.linode\.com/[0-9A-Za-z\-]+\.bin'},
    {"name": "Linode UK", "country": "UK", "url": "https://speedtest.london.linode.com/", "pattern": r'https://speedtest\.london\.linode\.com/[0-9A-Za-z\-]+\.bin'},
    {"name": "Linode JP", "country": "JP", "url": "https://speedtest.tokyo2.linode.com/", "pattern": r'https://speedtest\.tokyo2\.linode\.com/[0-9A-Za-z\-]+\.bin'},
    {"name": "Linode SG", "country": "SG", "url": "https://speedtest.singapore.linode.com/", "pattern": r'https://speedtest\.singapore\.linode\.com/[0-9A-Za-z\-]+\.bin'},
    {"name": "Azure Global", "country": "GLOBAL", "url": "https://www.azurespeed.com/Azure/Download", "pattern": r'https://azurespeedtestfiles\.blob\.core\.windows\.net/blobtestfiles/test[0-9a-zA-Z]+\.db'},
    {"name": "AWS S3 US East", "country": "US", "url": "https://speedtest.s3.amazonaws.com/", "pattern": r'https://speedtest\.s3\.amazonaws\.com/[0-9A-ZaZ]+\.bin'},
    {"name": "DigitalOcean NYC1", "country": "US", "url": "https://s3.amazonaws.com/speedtest-nyc1.digitalocean.com/", "pattern": r'https://s3\.amazonaws\.com/speedtest-nyc1\.digitalocean\.com/[0-9A-Za-z]+\.test'},
]

def is_alive(url):
    try:
        r = requests.head(url, timeout=10)
        return r.status_code == 200
    except Exception:
        return False

def file_size_from_url(url):
    m = re.search(r'([0-9]+)(MB|GB|Mb|Gb)', url)
    return m.group(0) if m else "file"

def main():
    sites = []
    for mirror in mirror_pages:
        try:
            resp = requests.get(mirror["url"], timeout=15)
            urls = set(re.findall(mirror["pattern"], resp.text))
            for url in urls:
                if is_alive(url):
                    sites.append({
                        "name": f"{mirror['name']} {file_size_from_url(url)}",
                        "url": url,
                        "country": mirror["country"]
                    })
        except Exception as e:
            print(f"Failed to fetch {mirror['url']}: {e}")
    with open("../sites.jsonc", "w") as f:
        json.dump(sites, f, indent=2)
    print(f"Updated sites.jsonc with {len(sites)} alive entries.")

if __name__ == "__main__":
    main()
