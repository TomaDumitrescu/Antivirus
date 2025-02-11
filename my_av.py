#!/usr/bin/python3
from urllib.parse import urlparse
import ipaddress
import string

# URL analyser

risky_words = [".exe", ".onion", ".bat", ".vbs", ".sh", ".pl\0", ".py\0", ".vbe", ".apk", "iso",
               ".bin", ".doc", "www1", "www2", "www3", "www-i1", "www-i2", "webhostapp", ".dat",
               "/exe/"]
phishing_domains = ["facebook", "instagram", "paypal", "google", "amazon", "tiktok", "bankofamerica",
                    "github", "twitter", "snapchat", "yahoo", "protonmail", "spotify", "youtube",
                    "netflix", "revolut", "linkedin", "wordpress", "origin", "steam", "microsoft",
                    "cloudfare", "apple", "samsung", "orange", "vodafone", "ebay", "emag", "primevideo",
                    "whatsapp", "office", "chase", "stripe", "aeon", "coinbase", "unicredit",
                    "allegro", "fedex", "usps", "crypto", "skype", "uber", "chatgpt", "gemini", "adobe"]

num_letter_f = 12

def get_domain(url):
    if "://" not in url:
        url = "http://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if domain.startswith("www."):
        domain = domain[4:]

    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        data = domain.split('.')
        name = str()
        for i in range(min(3, len(data))):
            if len(data[i]) > len(name):
                name = data[i]
    
        return name


def database_test(url):
    with open('data/urls/domains_database') as db:
        for line in db:
            infected = get_domain(line.strip())
            if infected in url:
                return 1

    return 0

def keywords_test(url):
    for word in risky_words:
        if word in url:
            return 1
    return 0

def regex_test(url):
    # numerical-letters rapport
    domain_name = get_domain(url)
    num_digits = 0
    for c in domain_name:
        if c.isdigit():
            num_digits += 1

    if (num_digits / len(domain_name)) * 100 >= num_letter_f:
        return 1
    
    # mispelling for well-known domains
    for word in phishing_domains:
        sym_diff = 0
        for i in range(min(len(word), len(domain_name))):
            if word[i] != domain_name[i]:
                sym_diff += 1

        sym_diff += max(len(word), len(domain_name)) - min(len(word), len(domain_name))
        if sym_diff == 1 or sym_diff == 2 or (word in domain_name and word != domain_name):
            return 1

    # veryfying if there are ips in the address
    for word in url.split("/"):
        try:
            ipaddress.ip_address(word)
            return 1
        except ValueError:
            wrong_ip_format = word.split('.')
            ok = 1
            for num in wrong_ip_format:
                if not num.isdigit():
                    ok = 0
                    break

            if ok == 1 and len(wrong_ip_format) >= 4:
                return 1
            continue
    
    # checking for strange names
    fq = {}
    for c in domain_name:
        fq[c] = fq.get(c, 0) + 1
    
    for c in string.ascii_lowercase:
        if fq.get(c, 0) >= 7:
            return 1
    
    if fq.get('j', 0) + fq.get('q', 0) + fq.get('w', 0) + fq.get('x', 0) + fq.get('y', 0) + fq.get('z', 0) >= 5:
        return 1
    
    return 0

def url_check(url):
   return database_test(url) or keywords_test(url) or regex_test(url)

with open('data/urls/urls.in', 'r') as urls_in, open('urls-predictions.out', 'w') as urls_out:
    for line in urls_in:
        url = line.strip()
        urls_out.write(f"{url_check(url)}\n")

# Traffic analyser
def flow_duration_payload_test(traffic):
    data = traffic.split(',')
    flow_payload = data[len(data) - 1]
    
    if flow_payload == '0.0':
        return 0

    flow_duration = data[4].split(' ')
    days = flow_duration[0]
    daytime = flow_duration[2].split(':')
    hours = daytime[0]
    minutes = daytime[1]
    seconds = daytime[2]
    
    if (days != "0" or hours != "00" or minutes != "00" or seconds[0] != '0' or
        (seconds[1] != '0' and seconds[1] != '1') or (seconds[1] == "1" and len(seconds) >= 3)):
        return 1
    
    return 0

def traffic_check(traffic):
    return flow_duration_payload_test(traffic)

with open('data/traffic/traffic.in', 'r') as traffic_in, open('traffic-predictions.out', 'w') as traffic_out:
    lines = traffic_in.readlines()[1:]
    for line in lines:
        traffic = line.strip()
        traffic_out.write(f"{traffic_check(traffic)}\n")
