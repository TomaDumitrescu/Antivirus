#!/usr/bin/python3

# URL analyser
def database_test(url):
    return 0

def keywords_test(url):
    return 0

def regex_test(url):
    return 0

def url_check(url):
   return database_test(url) and keywords_test(url) and regex_test(url)

with open('data/urls/urls.in', 'r') as urls_in, open('urls-predictions.out', 'w') as urls_out:
    for line in urls_in:
        url = line.strip()
        urls_out.write(f"{url_check(url)}\n")

# Traffic analyser
def traffic_check(traffic):
    return 0

with open('data/traffic/traffic.in', 'r') as traffic_in, open('traffic-predictions.out', 'w') as traffic_out:
    for line in traffic_in:
        traffic = line.strip()
        traffic_out.write(f"{traffic_check(traffic)}\n")