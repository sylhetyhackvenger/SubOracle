#!/usr/bin/python

import requests
import json
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import socket
import ssl
import whois
import re
from datetime import datetime, timedelta
import hashlib
import base64
import ipaddress
from collections import defaultdict, Counter
import random
import os
import traceback
import sqlite3
import signal
import logging
import subprocess
import tempfile
import shutil
import gzip
import zlib
import binascii
import struct
import uuid
import string
import itertools
from typing import Dict, List, Set, Tuple, Optional, Any, Union
import queue
import heapq
import math
import statistics
import csv
import xml.etree.ElementTree as ET
from email.parser import BytesParser
from email.policy import default
import pickle
import urllib.parse

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except:
    SELENIUM_AVAILABLE = False

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ORANGE = '\033[38;5;208m'
    PURPLE = '\033[38;5;141m'
    PINK = '\033[38;5;206m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLINK = '\033[5m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'

class Scanner:
    def __init__(self, domain, threads=30, timeout=15, verbose=True):
        self.original_input = domain
        self.domain = self.clean_domain(domain)
        self.threads = min(threads, 50)
        self.timeout = timeout
        self.verbose = True
        self.start_time = time.time()
        
        self.subdomains = set()
        self.alive = {}
        self.dns_records = {}
        self.technologies = {}
        self.vulnerabilities = []
        self.ports = {}
        self.ssl_info = {}
        self.geo_info = {}
        self.cloud_assets = {}
        self.takeover_candidates = []
        self.api_endpoints = {}
        self.emails_found = []
        self.waf_info = {}
        self.dnssec_info = {}
        self.caa_records = {}
        self.hsts_info = {}
        self.server_info = {}
        self.whois_info = {}
        self.email_security = {}
        self.hidden_paths = {}
        self.response_times = {}
        self.full_urls = []
        self.screenshots = {}
        self.ssl_certs = {}
        self.cve_results = {}
        self.exploit_results = {}
        self.backup_files = {}
        self.git_repos = {}
        self.dns_history = {}
        self.zone_transfer_results = {}
        self.reverse_dns = {}
        self.asn_info = {}
        self.bgp_info = {}
        self.subdomain_permutations = set()
        self.cookies = {}
        self.headers = {}
        self.redirects = {}
        self.forms = {}
        self.js_files = {}
        self.css_files = {}
        self.images = {}
        self.favicons = {}
        self.sitemaps = {}
        self.robots_txt = {}
        self.security_txt = {}
        self.csp_reports = {}
        self.feature_policy = {}
        self.permissions_policy = {}
        self.cors_headers = {}
        self.sri_hashes = {}
        self.email_security_results = []
        self.wayback_urls = []
        self.all_dns_history = {}
        self.extracted_js = {}
        self.extracted_css = {}
        
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        try:
            requests.packages.urllib3.disable_warnings()
        except:
            pass
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
        ]
        self.ua_index = 0
        
        self.nameservers = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9']
        self.wordlist = self.load_wordlist()
        self.cve_cache = self.load_cve_cache()
        
        self.stats = {
            'total': 0, 'alive': 0, 'vulnerabilities': 0,
            'errors': 0, 'requests': 0, 'sources': [],
            'takeovers': 0, 'api_endpoints': 0, 'cloud_assets': 0,
            'emails_found': 0, 'full_urls': 0, 'dns_records': 0,
            'ports_found': 0, 'technologies_found': 0,
            'ssl_certs': 0, 'waf_detected': 0, 'cves_found': 0,
            'js_files': 0, 'css_files': 0, 'images': 0,
            'cookies': 0, 'redirects': 0, 'forms': 0,
            'backup_files': 0, 'git_repos': 0, 'wayback_urls': 0,
            'screenshots': 0, 'cves': 0, 'exploits': 0,
            'reverse_dns': 0, 'bgp': 0, 'permutations': 0,
            'hidden_paths_found': 0
        }
        
        self.db_path = f"{self.domain}_complete_scan.db"
        self.init_database()
        self.print_banner()
    
    def clean_domain(self, input_domain):
        input_domain = input_domain.strip().lower()
        if '://' in input_domain:
            input_domain = urlparse(input_domain).netloc
        if input_domain.startswith('www.'):
            input_domain = input_domain[4:]
        input_domain = input_domain.split('/')[0].split('?')[0].split('#')[0]
        if ':' in input_domain:
            input_domain = input_domain.split(':')[0]
        return input_domain
    
    def load_wordlist(self):
        wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3',
            'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
            'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
            'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'download',
            'dns', 'piwik', 'stats', 'dashboard', 'portal', 'manage', 'start', 'info', 'apps',
            'video', 'sip', 'dns2', 'api', 'cdn', 'mssql', 'remote', 'server', 'ftp2', 'ns4',
            'stage', 'vpn2', 'ns5', 'backup', 'mx2', 'proxy', 'sap', 'git', 'svn', 'jenkins',
            'jira', 'confluence', 'bitbucket', 'nexus', 'artifactory', 'sonar', 'kibana',
            'elasticsearch', 'logstash', 'grafana', 'prometheus', 'alertmanager',
            'test', 'stage', 'prod', 'production', 'staging', 'dev', 'development',
            'uat', 'qa', 'quality', 'preprod', 'pre-production', 'sandbox', 'playground'
        ]
        return wordlist
    
    def load_cve_cache(self):
        return {
            'nginx': {'cve': 'CVE-2021-23017', 'severity': 'MEDIUM', 'description': 'Nginx integer overflow vulnerability'},
            'apache': {'cve': 'CVE-2021-41773', 'severity': 'HIGH', 'description': 'Apache path traversal vulnerability'},
            'tomcat': {'cve': 'CVE-2021-33037', 'severity': 'HIGH', 'description': 'Tomcat information disclosure'},
            'php': {'cve': 'CVE-2021-21703', 'severity': 'HIGH', 'description': 'PHP buffer overflow vulnerability'},
            'wordpress': {'cve': 'CVE-2021-29447', 'severity': 'MEDIUM', 'description': 'WordPress XXE vulnerability'},
            'drupal': {'cve': 'CVE-2020-28949', 'severity': 'HIGH', 'description': 'Drupal RCE vulnerability'},
            'joomla': {'cve': 'CVE-2021-23132', 'severity': 'MEDIUM', 'description': 'Joomla XSS vulnerability'},
            'django': {'cve': 'CVE-2021-45452', 'severity': 'MEDIUM', 'description': 'Django path traversal'},
            'flask': {'cve': 'CVE-2021-32618', 'severity': 'LOW', 'description': 'Flask security bypass'},
            'rails': {'cve': 'CVE-2020-8165', 'severity': 'HIGH', 'description': 'Rails deserialization RCE'},
            'express': {'cve': 'CVE-2021-21315', 'severity': 'MEDIUM', 'description': 'Express path traversal'},
            'openssl': {'cve': 'CVE-2021-3711', 'severity': 'CRITICAL', 'description': 'OpenSSL SM2 vulnerability'},
            'heartbleed': {'cve': 'CVE-2014-0160', 'severity': 'CRITICAL', 'description': 'OpenSSL heartbleed vulnerability'},
            'shellshock': {'cve': 'CVE-2014-6271', 'severity': 'CRITICAL', 'description': 'Bash shellshock vulnerability'},
            'log4j': {'cve': 'CVE-2021-44228', 'severity': 'CRITICAL', 'description': 'Log4j JNDI RCE vulnerability'},
            'struts': {'cve': 'CVE-2017-5638', 'severity': 'HIGH', 'description': 'Apache Struts RCE vulnerability'},
            'spring4shell': {'cve': 'CVE-2022-22965', 'severity': 'CRITICAL', 'description': 'Spring4Shell RCE vulnerability'}
        }
    
    def init_database(self):
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            
            tables = [
                '''CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT, ip TEXT,
                    alive INTEGER, status_code INTEGER, title TEXT,
                    server TEXT, response_time REAL, location TEXT,
                    data TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    vulnerability TEXT, severity TEXT, cve_id TEXT,
                    exploit_available INTEGER, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    record_type TEXT, record_value TEXT, ttl INTEGER,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    port INTEGER, service TEXT, banner TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    tech_type TEXT, tech_value TEXT, version TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    email TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS full_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    full_url TEXT, status_code INTEGER,
                    content_type TEXT, content_length INTEGER,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS ssl_certs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    issuer TEXT, subject TEXT,
                    not_before TIMESTAMP, not_after TIMESTAMP,
                    serial TEXT, cipher TEXT, protocol TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    cve_id TEXT, severity TEXT, description TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS screenshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    screenshot_path TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS api_endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    endpoint TEXT, method TEXT,
                    status_code INTEGER, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS hidden_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    path TEXT, status_code INTEGER,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS redirects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    source_url TEXT, target_url TEXT,
                    status_code INTEGER, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS cookies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    cookie_name TEXT, cookie_value TEXT,
                    secure INTEGER, httponly INTEGER, samesite TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS email_security (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, record_type TEXT,
                    record_value TEXT, status TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS security_headers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    header_name TEXT, header_value TEXT,
                    status TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS cors_headers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    header_name TEXT, header_value TEXT,
                    status TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS dnssec_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, algorithm TEXT,
                    status TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS caa_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, flag INTEGER,
                    tag TEXT, value TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS wayback_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, url TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS reverse_dns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, ip TEXT,
                    ptr_record TEXT, scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS bgp_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, ip TEXT,
                    asn TEXT, prefix TEXT, as_name TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS zone_transfer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, nameserver TEXT,
                    record_name TEXT, record_type TEXT, record_value TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS dns_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, record_type TEXT,
                    record_value TEXT, first_seen TIMESTAMP, last_seen TIMESTAMP,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS cloud_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    provider TEXT, record_type TEXT, record_value TEXT,
                    scan_time TIMESTAMP
                )''',
                '''CREATE TABLE IF NOT EXISTS takeover_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, subdomain TEXT,
                    service TEXT, pattern TEXT, status_code INTEGER,
                    scan_time TIMESTAMP
                )'''
            ]
            
            for query in tables:
                self.cursor.execute(query)
            self.conn.commit()
        except Exception as e:
            print(f"[!] Database error: {e}")
    
    def print_banner(self):
        banner = f"""
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⡴⠒⠁{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⣿⣿⠟⠁⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⣛⣻⣤⣤⣶⠶⠚⠋⠉⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢛⣋⣭⣴⣶⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠀⢠⡿⠀⠀⣀⡤⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⡿⠟⣋⣥⣴⣾⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⣠⣾⢃⣴⡿⠁⣠⣾⣯⣤⣴⣾⣿⣋⡁⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⠿⢋⣡⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⣴⣟⣵⣿⢏⣴⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠷⠦⣄⠀⠀⠀⢻⣿⣿⣿⡿⠋⣡⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⣸⣯⣾⣿⢧⣻⣿⡞⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠈⢿⣿⠋⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⢀⣴⣿⢿⣿⣿⣿⣿⣝⣺⠟⠋⠉⠈⠉⠻⣿⣿⣿⣿⣿⣿⣿⢿⣆⠀⠀⠀⠘⣯⠀⢉⣉⣭⣭⣭⣭⣭⣙⣛⣛⠻⠿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⢻⣿⣤⣾⡿⣿⣿⣿⡿⠷⠖⠂⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⡂⠘⠇⠀⠀⠀⣿⣆⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣭⣟⣻⢿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⣴⣠⣴⣿⣿⠿⣿⣧⣿⣿⠟⠛⠓⠀⠀⠀⠀⠀⠀⣸⣽⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⣸⣿⣿⡄⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠛⠛⠛⠚⠳⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⢿⣧⣿⡿⠅⣼⠏⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⢀⣚⠿⣷⣿⣿⣿⣿⠻⣿⠀⠀⠀⣰⣿⣿⣿⠇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠈⠿⠑⠬⠴⣃⣴⣿⠀⠀⠀⠀⠀⠀⠀⢀⠺⣿⡿⣱⣿⣿⣿⣿⠃⠠⠃⠀⢀⣼⣿⣿⣿⠏⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠈⠙⠛⠋⠉⠀⠀⠀⠀⠀⣴⣿⣿⡗⣼⣿⣿⣿⣿⣿⡀⠀⢀⣴⣿⣿⠿⢛⠅⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣦⣭⣽⢸⣿⣿⣿⣿⣯⠘⠇⠠⢛⣩⣭⣶⢞⣥⣾⣿⣿⣿⣿⣿⣿⣿⣿⠟⠛⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⢿⣿⡏⣿⣿⣿⣿⣿⣿⣷⣖⣴⣿⣿⢟⣵⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⣷⣶⣶⣶⡶⠤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⣶⣾⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠿⢟⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⡿⣿⠿⢟⣛⣛⣻⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⣶⠿⣦⡉⣿⠀⠀⠀⠻⣛⣵⣿⣧⢿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⡿⠼⠋⠈⠀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⡴⢻⣿⣿⣿⣿⣷⣄⣀⡀⠀⢙⡻⢿⣎⢻⣿⣿⣿⣿⢹⣿⢻⡿⠃⠋⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⡟⠀⠀⠈⣹⡿⠿⢿⣿⣿⣿⣿⣷⡮⠁⠙⢿⣿⣿⡌⠉⠀⠀⠀⠀⠀⠀⢀⠀⠈⠿⣿⣿⣿⣿⣿⡿⠿⣿⠿⢿⣿⣿⣿⣿⣇⠙⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠈⠲⠞⠏⠀⠀⠀⠀⠉⠛⠛⢿⠁⠀⣰⣿⣿⣿⡿⠦⠄⠀⠀⠀⢠⣞⣿⣦⣄⡀⠈⠛⠻⢿⣿⣷⡀⠀⠈⢿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣄⠀⠀⠀⠀⣡⣾⣿⡿⠟⠛⠓⠀⠀⠀⠀⣠⣟⢩⣿⢿⣿⣿⣿⣷⣶⣶⣿⣿⣧⠀⠀⠸⣿⣿⣿⣿⣿⣿⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣋⣙⣿⣶⣶⣿⣿⠟⠉⠀⠀⠀⠀⣀⣴⣾⣿⣷⣇⡿⣇⣾⣻⣧⣀⠀⠈⠉⠛⠿⣿⣧⡀⠀⣿⣿⣿⣿⣿⣿⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡟⢩⣽⠿⠛⠛⠛⢻⣄⠀⠀⠀⣠⣾⣿⣿⡿⠟⠛⠉⠁⠉⠚⠾⣿⣿⣧⡀⠀⠀⠀⠀⡿⠁⠀⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠂⠸⣇⠀⠀⠀⠀⣰⠏⠀⠀⣴⣿⣿⡿⠋⠀⠀⠀⠀⣀⡀⠀⠀⠈⢿⣿⣷⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⠁⠀⠀⠀⢠⡾⠁⠀⠀⠀⠀⠘⣿⣿⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣟⠀⠀⠀⠀⢿⣇⠀⠀⠀⠀⠀⣸⣿⡟⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠘⢿⣶⣤⣤⣤⣾⣿⠟⠁⠀⠀⠀⣠⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣧⡀⠀⠀⠀⠀⠈⠙⠛⠋⠉⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣦⣄⣀⠀⠀⠀⠀⠀⣀⣠⣤⣾⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}
{Colors.PURPLE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⢿⣿⣿⣿⣿⡿⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Colors.RESET}

{Colors.MAGENTA}███████╗██╗   ██╗██████╗  ██████╗ ██████╗  █████╗  ██████╗██╗     ███████╗{Colors.RESET}
{Colors.MAGENTA}██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔════╝{Colors.RESET}
{Colors.MAGENTA}███████╗██║   ██║██████╔╝██║   ██║██████╔╝███████║██║     ██║     █████╗  {Colors.RESET}
{Colors.MAGENTA}╚════██║██║   ██║██╔══██╗██║   ██║██████╔╝██╔══██║██║     ██║     ██╔══╝  {Colors.RESET}
{Colors.MAGENTA}███████║╚██████╔╝██████╔╝╚██████╔╝██║  ██║██║  ██║╚██████╗███████╗███████╗{Colors.RESET}
{Colors.MAGENTA}╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝{Colors.RESET}

{Colors.RED}╔═══════════════════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.RED}║{Colors.YELLOW}                                                                   ║{Colors.RESET}
{Colors.RED}║{Colors.YELLOW}           {Colors.BLINK}🔥 SUBORACLE 🔥{Colors.RESET}{Colors.YELLOW}            ║{Colors.RESET}
{Colors.RED}║{Colors.YELLOW}                                                                   ║{Colors.RESET}
{Colors.RED}║{Colors.CYAN}                  SUBDOMAIN RECONNAISSANCE FRAMEWORK                  ║{Colors.RESET}
{Colors.RED}║{Colors.CYAN}                        GRAY HAT HACKING TOOL                            ║{Colors.RESET}
{Colors.RED}║{Colors.YELLOW}                                                                   ║{Colors.RESET}
{Colors.RED}║{Colors.MAGENTA}         Author: {Colors.WHITE}SYLHETYHACKVENGER (THE-ERROR808)        ║{Colors.RESET}
{Colors.RED}║{Colors.MAGENTA}                                                                   ║{Colors.RESET}
{Colors.RED}║{Colors.ORANGE}         ⚠️  WARNING: For Educational & Security Testing Only        ║{Colors.RESET}
{Colors.RED}║{Colors.ORANGE}         ⚠️  Unauthorized Access is Prohibited by Law           ║{Colors.RESET}
{Colors.RED}║{Colors.ORANGE}                                                                   ║{Colors.RESET}
{Colors.RED}╚═══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
        print(f"{Colors.GREEN}[+] Target: {Colors.YELLOW}{self.domain}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Input: {Colors.YELLOW}{self.original_input}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Threads: {Colors.YELLOW}{self.threads}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Timeout: {Colors.YELLOW}{self.timeout}s{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Mode: {Colors.YELLOW}VERBOSE (Full Details){Colors.RESET}\n")
    
    def get_user_agent(self):
        ua = self.user_agents[self.ua_index]
        self.ua_index = (self.ua_index + 1) % len(self.user_agents)
        return ua
    
    def safe_request(self, url, max_retries=3, **kwargs):
        for attempt in range(max_retries):
            try:
                kwargs['timeout'] = kwargs.get('timeout', self.timeout)
                kwargs['verify'] = False
                if 'headers' not in kwargs:
                    kwargs['headers'] = {}
                kwargs['headers']['User-Agent'] = self.get_user_agent()
                
                response = self.session.get(url, **kwargs)
                self.stats['requests'] += 1
                return response
            except:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
        return None
    
    def dns_resolve(self, domain, record_type='A'):
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.nameservers
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            return [str(r) for r in answers]
        except:
            try:
                if record_type == 'A':
                    ip = socket.gethostbyname(domain)
                    return [ip]
            except:
                pass
            return None
    
    def advanced_dns_enum(self, domain):
        all_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'DS', 'DNSKEY', 'NAPTR', 'LOC', 'HINFO', 'RP', 'TLSA', 'SSHFP', 'IPSECKEY', 'DHCID']
        
        for record_type in record_types:
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.nameservers
                resolver.timeout = 5
                resolver.lifetime = 10
                answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
                if answers:
                    all_records[record_type] = [str(r) for r in answers]
                    print(f"    {Colors.CYAN}{record_type}{Colors.RESET}:")
                    for r in all_records[record_type]:
                        print(f"      {Colors.GREEN}→{Colors.RESET} {r}")
            except:
                pass
        
        try:
            ipv4 = socket.gethostbyname(domain)
            all_records['A_IPv4'] = [ipv4]
            print(f"    {Colors.CYAN}IPv4{Colors.RESET}:")
            print(f"      {Colors.GREEN}→{Colors.RESET} {ipv4}")
        except:
            pass
        
        try:
            addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET6)
            ipv6_addrs = []
            for addr in addrinfo:
                ip = addr[4][0]
                if ':' in ip:
                    ipv6_addrs.append(ip)
            if ipv6_addrs:
                all_records['AAAA_IPv6'] = ipv6_addrs
                print(f"    {Colors.CYAN}IPv6{Colors.RESET}:")
                for ip in ipv6_addrs:
                    print(f"      {Colors.GREEN}→{Colors.RESET} {ip}")
        except:
            pass
        
        return all_records
    
    def get_ip_geolocation(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = self.safe_request(url, max_retries=1, timeout=5)
            if response and response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    lat = data.get('lat')
                    lon = data.get('lon')
                    maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else None
                    return {
                        'ip': ip,
                        'country': data.get('country'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'lat': lat,
                        'lon': lon,
                        'maps_link': maps_link
                    }
        except:
            pass
        return None
    
    def resolve_all_dns_advanced(self):
        print(f"{Colors.CYAN}[+] Advanced DNS enumeration (all record types, IPv4, IPv6)...{Colors.RESET}")
        
        print(f"    {Colors.YELLOW}Main domain: {self.domain}{Colors.RESET}")
        records = self.advanced_dns_enum(self.domain)
        if records:
            self.dns_records[self.domain] = records
            self.stats['dns_records'] += len(records)
            
            if 'CAA' in records:
                self.caa_records[self.domain] = records['CAA']
            if 'DS' in records or 'DNSKEY' in records:
                self.dnssec_info[self.domain] = {
                    'has_dnssec': True,
                    'records': records.get('DS', []) + records.get('DNSKEY', [])
                }
        
        print(f"    {Colors.YELLOW}Subdomains: {len(self.subdomains)}{Colors.RESET}")
        for sub in list(self.subdomains):
            print(f"    {Colors.CYAN}{sub}{Colors.RESET}")
            records = self.advanced_dns_enum(sub)
            if records:
                self.dns_records[sub] = records
                self.stats['dns_records'] += len(records)
    
    def get_reverse_dns(self, ip):
        try:
            import dns.reversename
            import dns.resolver
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, 'PTR')
            if answers:
                return [str(r) for r in answers]
        except:
            pass
        return None
    
    def get_bgp_info(self, ip):
        try:
            url = f"https://api.bgpview.io/ip/{ip}"
            response = self.safe_request(url, max_retries=1, timeout=5)
            if response and response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok' and data.get('data'):
                    asn_data = data['data']
                    return {
                        'asn': asn_data.get('asn'),
                        'asn_name': asn_data.get('asn_name'),
                        'prefix': asn_data.get('prefix'),
                        'country': asn_data.get('country_code')
                    }
        except:
            pass
        return None
    
    def get_all_reverse_dns_bgp(self):
        print(f"{Colors.CYAN}[+] Getting Reverse DNS and BGP Information...{Colors.RESET}")
        all_ips = set()
        
        for domain, records in self.dns_records.items():
            if 'A_IPv4' in records:
                for ip in records['A_IPv4']:
                    all_ips.add(ip)
            if 'AAAA_IPv6' in records:
                for ip in records['AAAA_IPv6']:
                    all_ips.add(ip)
        
        if not all_ips:
            print(f"    {Colors.YELLOW}⚠ No IPs found for reverse DNS/BGP lookup{Colors.RESET}")
            return
        
        count = 0
        for ip in all_ips:
            ptr = self.get_reverse_dns(ip)
            if ptr:
                self.reverse_dns[ip] = ptr
                self.stats['reverse_dns'] += 1
                count += 1
                print(f"    {Colors.GREEN}{ip}{Colors.RESET} → {', '.join(ptr)}")
            
            bgp = self.get_bgp_info(ip)
            if bgp:
                self.bgp_info[ip] = bgp
                self.stats['bgp'] += 1
                print(f"    {Colors.CYAN}BGP{Colors.RESET} {ip}: AS{bgp.get('asn')} - {bgp.get('asn_name')}")
        
        if count == 0:
            print(f"    {Colors.YELLOW}⚠ No reverse DNS records found{Colors.RESET}")
    
    def dns_bruteforce(self):
        print(f"{Colors.CYAN}[+] DNS Bruteforce with wordlist...{Colors.RESET}")
        count = 0
        for prefix in self.wordlist:
            sub = f"{prefix}.{self.domain}"
            if sub in self.subdomains:
                continue
            try:
                socket.gethostbyname(sub)
                self.subdomains.add(sub)
                count += 1
                print(f"      {Colors.CYAN}→{Colors.RESET} {sub}")
            except:
                pass
        self.stats['total'] += count
        print(f"    {Colors.GREEN}✓ Found {count} subdomains via brute force{Colors.RESET}")
    
    def generate_permutations(self):
        print(f"{Colors.CYAN}[+] Generating subdomain permutations...{Colors.RESET}")
        base_parts = self.domain.split('.')
        if len(base_parts) >= 2:
            base = base_parts[0]
            tld = '.'.join(base_parts[1:])
            
            prefixes = ['www', 'mail', 'ftp', 'dev', 'test', 'staging', 'api', 'admin', 'blog', 'shop', 'app', 'web', 'mobile', 'secure']
            suffixes = ['app', 'dev', 'test', 'staging', 'prod', 'production', 'uat', 'qa', 'demo', 'sandbox']
            
            permutations = []
            for prefix in prefixes:
                permutations.append(f"{prefix}.{base}.{tld}")
            for suffix in suffixes:
                permutations.append(f"{base}{suffix}.{tld}")
                permutations.append(f"{base}-{suffix}.{tld}")
            permutations.append(f"{base}.{tld}")
            permutations.append(f"www{base}.{tld}")
            
            for perm in permutations:
                if perm not in self.subdomains:
                    self.subdomains.add(perm)
                    self.stats['permutations'] += 1
                    print(f"      {Colors.CYAN}→{Colors.RESET} {perm}")
    
    def zone_transfer_attempt(self):
        print(f"{Colors.CYAN}[+] Attempting Zone Transfer...{Colors.RESET}")
        if not DNS_AVAILABLE:
            print(f"    {Colors.YELLOW}⚠ DNS module not available{Colors.RESET}")
            return
        
        try:
            import dns.resolver
            import dns.query
            import dns.zone
            import dns.exception
            
            ns_records = self.dns_resolve(self.domain, 'NS')
            if not ns_records:
                print(f"    {Colors.YELLOW}⚠ No NS records found{Colors.RESET}")
                return
            
            for ns in ns_records:
                ns_ip = None
                try:
                    ns_ip = socket.gethostbyname(ns)
                except:
                    continue
                
                if not ns_ip:
                    continue
                
                try:
                    print(f"    {Colors.YELLOW}Testing: {ns} ({ns_ip}){Colors.RESET}")
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10))
                    if zone:
                        records = []
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    record_data = {
                                        'name': str(name),
                                        'type': dns.rdatatype.to_text(rdataset.rdtype),
                                        'value': str(rdata)
                                    }
                                    records.append(record_data)
                                    print(f"      {Colors.GREEN}{record_data['name']}{Colors.RESET} {Colors.CYAN}{record_data['type']}{Colors.RESET} → {record_data['value']}")
                        
                        self.zone_transfer_results[ns] = records
                        print(f"    {Colors.GREEN}✓ Zone transfer successful! Found {len(records)} records{Colors.RESET}")
                except Exception as e:
                    pass
        except:
            pass
        
        if not self.zone_transfer_results:
            print(f"    {Colors.YELLOW}⚠ Zone transfer failed (not supported){Colors.RESET}")
    
    def take_screenshot(self, subdomain):
        if not SELENIUM_AVAILABLE:
            return None
        
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            
            driver = webdriver.Chrome(options=options)
            url = f"https://{subdomain}"
            try:
                driver.get(url)
                time.sleep(2)
                screenshot_path = f"screenshots/{subdomain}.png"
                os.makedirs('screenshots', exist_ok=True)
                driver.save_screenshot(screenshot_path)
                driver.quit()
                self.screenshots[subdomain] = screenshot_path
                self.stats['screenshots'] += 1
                print(f"    {Colors.GREEN}{subdomain}{Colors.RESET} Screenshot saved: {screenshot_path}")
                return screenshot_path
            except:
                driver.quit()
                return None
        except:
            return None
    
    def scan_cves(self, subdomain):
        cves = []
        
        try:
            response = self.safe_request(f"http://{subdomain}", max_retries=1, timeout=3)
            if response:
                headers = response.headers
                server = headers.get('Server', '').lower()
                powered = headers.get('X-Powered-By', '').lower()
                content = response.text.lower()
                
                for tech_name, info in self.cve_cache.items():
                    if tech_name in server or tech_name in powered or tech_name in content:
                        cves.append({
                            'cve_id': info['cve'],
                            'severity': info['severity'],
                            'description': info['description']
                        })
                        self.stats['cves'] += 1
                        self.stats['cves_found'] += 1
                        print(f"    {Colors.RED}⚠ {subdomain}: {tech_name} ({info['cve']}) - {info['severity']}{Colors.RESET}")
        except:
            pass
        
        self.cve_results[subdomain] = cves
        return cves
    
    def check_exploits(self, subdomain):
        exploits = []
        exploit_patterns = [
            ('XSS', '<script>alert', 'MEDIUM', 'Cross-Site Scripting'),
            ('SQL Injection', 'sql error', 'CRITICAL', 'SQL Injection'),
            ('LFI', '../../', 'HIGH', 'Local File Inclusion'),
            ('RCE', 'rce', 'CRITICAL', 'Remote Code Execution'),
            ('Path Traversal', '../', 'HIGH', 'Path Traversal'),
            ('Command Injection', '|', 'CRITICAL', 'Command Injection'),
            ('Directory Listing', 'Index of /', 'MEDIUM', 'Directory Listing'),
            ('Backup File', '.bak', 'MEDIUM', 'Backup File Exposure'),
            ('Git Exposure', '.git', 'HIGH', 'Git Repository Exposure'),
            ('SVN Exposure', '.svn', 'HIGH', 'SVN Repository Exposure'),
            ('Env File', '.env', 'HIGH', 'Environment File Exposure'),
            ('PHPInfo', 'phpinfo()', 'MEDIUM', 'PHP Info Exposure')
        ]
        
        try:
            for path in ['/', '/admin', '/login', '/wp-admin', '/phpmyadmin', '/cpanel']:
                url = f"http://{subdomain}{path}"
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response:
                    content = response.text.lower()
                    for exploit_name, pattern, severity, desc in exploit_patterns:
                        if pattern.lower() in content:
                            exploits.append({
                                'exploit': exploit_name,
                                'severity': severity,
                                'path': path,
                                'description': desc
                            })
                            self.stats['exploits'] += 1
                            print(f"    {Colors.RED}⚠ {subdomain}: {exploit_name} ({desc}) - {severity}{Colors.RESET}")
        except:
            pass
        
        self.exploit_results[subdomain] = exploits
        return exploits
    
    def extract_subdomains(self, text):
        found = set()
        pattern = r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(self.domain)
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            found.add(match.lower().strip())
        return found
    
    def get_subdomains_wayback(self):
        try:
            api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey"
            response = self.safe_request(api_url)
            
            if response and response.status_code == 200:
                cleaned_urls = set()
                count = 0
                print(f"    {Colors.GREEN}✓ Retrieved URLs from Wayback Machine{Colors.RESET}")
                
                for line in response.text.splitlines():
                    if line:
                        cleaned_url = line.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0].replace('www.', '').rstrip('.')
                        if '@' not in cleaned_url and self.domain in cleaned_url:
                            cleaned_urls.add(cleaned_url)
                            self.wayback_urls.append(line.strip())
                
                for sub in sorted(cleaned_urls):
                    if sub and sub not in self.subdomains:
                        self.subdomains.add(sub)
                        count += 1
                        print(f"      {Colors.CYAN}→{Colors.RESET} {sub}")
                
                self.stats['wayback_urls'] += len(self.wayback_urls)
                return count
            else:
                return 0
        except Exception as e:
            print(f"    {Colors.RED}✗ Error: {e}{Colors.RESET}")
            return 0
    
    def get_subdomains_hackertarget(self):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.safe_request(url)
            if not response or response.status_code != 200:
                return 0
            count = 0
            lines = response.text.split('\n')
            for line in lines:
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if sub and self.domain in sub and sub not in self.subdomains:
                        self.subdomains.add(sub.lower())
                        count += 1
                        print(f"      {Colors.CYAN}→{Colors.RESET} {sub.lower()}")
            return count
        except:
            return 0
    
    def get_subdomains_commonspeak(self):
        prefixes = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 
                   'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3',
                   'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
                   'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
                   'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'download',
                   'dns', 'piwik', 'stats', 'dashboard', 'portal', 'manage', 'start', 'info', 'apps',
                   'video', 'sip', 'dns2', 'api', 'cdn', 'mssql', 'remote', 'server', 'ftp2', 'ns4',
                   'stage', 'vpn2', 'ns5', 'backup', 'mx2', 'proxy', 'sap', 'git', 'svn', 'jenkins',
                   'jira', 'confluence', 'bitbucket', 'nexus', 'artifactory', 'sonar', 'kibana',
                   'elasticsearch', 'logstash', 'grafana', 'prometheus', 'alertmanager']
        count = 0
        for prefix in prefixes:
            sub = f"{prefix}.{self.domain}"
            if sub not in self.subdomains:
                self.subdomains.add(sub)
                count += 1
                print(f"      {Colors.CYAN}→{Colors.RESET} {sub}")
        return count
    
    def scan_port(self, subdomain, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((subdomain, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    def scan_common_ports(self, subdomain):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                        1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 27017, 9200, 9300,
                        5000, 5432, 6379, 11211, 27017, 27018, 27019, 28017]
        open_ports = []
        for port in common_ports:
            result = self.scan_port(subdomain, port)
            if result:
                open_ports.append(result)
                print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}Port {port} open{Colors.RESET}")
        return open_ports
    
    def scan_all_ports(self):
        print(f"{Colors.CYAN}[+] Scanning common ports for all subdomains...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_common_ports, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    ports = future.result()
                    if ports:
                        self.ports[sub] = ports
                        self.stats['ports_found'] += len(ports)
                        print(f"    {Colors.GREEN}{sub}{Colors.RESET}: {len(ports)} open ports")
                except:
                    pass
    
    def detect_technologies(self, subdomain):
        techs = {}
        try:
            url = f"http://{subdomain}"
            response = self.safe_request(url, max_retries=1, timeout=5)
            if response:
                techs = self.parse_technologies(response)
        except:
            pass
        
        try:
            url = f"https://{subdomain}"
            response = self.safe_request(url, max_retries=1, timeout=5)
            if response:
                techs.update(self.parse_technologies(response))
        except:
            pass
        
        return techs
    
    def parse_technologies(self, response):
        techs = {}
        headers = response.headers
        content = response.text[:10000] if response.text else ''
        
        if 'Server' in headers:
            techs['Server'] = headers['Server']
            self.server_info[response.url] = headers['Server']
        if 'X-Powered-By' in headers:
            techs['X-Powered-By'] = headers['X-Powered-By']
        
        frameworks = {
            'laravel': ['laravel', 'csrf-token', 'laravel_session'],
            'django': ['django', 'csrftoken', '__cfduid'],
            'rails': ['rails', 'authenticity_token'],
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'joomla': ['joomla', 'com_content'],
            'drupal': ['drupal', 'drupal.settings'],
            'asp.net': ['asp.net', '__viewstate', '__eventvalidation'],
            'flask': ['flask', '__flask_session'],
            'express': ['express', 'connect.sid'],
            'nginx': ['nginx'],
            'apache': ['apache'],
            'iis': ['microsoft-iis'],
            'tomcat': ['tomcat'],
            'jetty': ['jetty'],
            'nodejs': ['node.js'],
            'php': ['php', 'phpsessid'],
            'react': ['_next', '__next', 'react'],
            'angular': ['angular', 'ng-version'],
            'vue': ['vue', 'vue-'],
            'bootstrap': ['bootstrap', 'btn-primary'],
            'jquery': ['jquery', '$('],
            'font-awesome': ['font-awesome', 'fa-'],
        }
        
        content_lower = content.lower()
        for framework, markers in frameworks.items():
            for marker in markers:
                if marker.lower() in content_lower or marker in headers:
                    techs[framework] = 'detected'
                    break
        
        return techs
    
    def detect_all_technologies(self):
        print(f"{Colors.CYAN}[+] Detecting technologies for all subdomains...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.detect_technologies, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    techs = future.result()
                    if techs:
                        self.technologies[sub] = techs
                        self.stats['technologies_found'] += len(techs)
                        print(f"    {Colors.GREEN}{sub}{Colors.RESET}: {', '.join(techs.keys())}")
                except:
                    pass
    
    def check_takeover(self, subdomain):
        takeover_patterns = [
            ('404', '404 Not Found'),
            ('does not exist', 'Domain does not exist'),
            ('not found', 'Not Found'),
            ('no such app', 'No such app'),
            ('heroku', 'Heroku'),
            ('github pages', 'GitHub Pages'),
            ('s3.amazonaws.com', 'AWS S3'),
            ('storage.googleapis.com', 'Google Cloud Storage'),
            ('azurewebsites.net', 'Azure Web App'),
            ('cloudfront.net', 'CloudFront'),
            ('elb.amazonaws.com', 'AWS ELB'),
            ('pages.github.com', 'GitHub Pages'),
            ('github.io', 'GitHub Pages'),
            ('bitbucket.io', 'Bitbucket'),
            ('gitlab.io', 'GitLab'),
            ('surge.sh', 'Surge'),
            ('netlify.com', 'Netlify'),
            ('vercel.app', 'Vercel'),
            ('firebaseapp.com', 'Firebase'),
            ('web.app', 'Firebase'),
            ('myshopify.com', 'Shopify'),
            ('shopify.com', 'Shopify'),
            ('NoSuchBucket', 'AWS S3'),
            ('The specified bucket does not exist', 'AWS S3'),
            ('Error 404 - Web app not found', 'Azure'),
            ('Site does not exist', 'Ghost'),
            ('There isn\'t a GitHub Pages site here', 'GitHub Pages'),
            ('No such app', 'Heroku'),
            ('Domain Not Found', 'HubSpot'),
            ('site not found', 'Netlify'),
            ('Unknown Host', 'ReadTheDocs'),
            ('render.com/404', 'Render'),
            ('project not found', 'Surge'),
            ('DEPLOYMENT_NOT_FOUND', 'Vercel'),
            ('The site you were looking for couldn\'t be found', 'WP Engine')
        ]
        
        try:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                try:
                    start_time = time.time()
                    response = self.safe_request(url, max_retries=1, timeout=5)
                    response_time = time.time() - start_time
                    if response:
                        self.response_times[subdomain] = response_time
                        self.alive[subdomain] = True
                        self.stats['alive'] += 1
                        content = response.text.lower() if response.text else ''
                        for pattern, service in takeover_patterns:
                            if pattern.lower() in content:
                                self.takeover_candidates.append({
                                    'subdomain': subdomain,
                                    'url': url,
                                    'pattern': pattern,
                                    'service': service,
                                    'status': response.status_code
                                })
                                self.stats['takeovers'] += 1
                                print(f"    {Colors.RED}⚠ TAKEOVER CANDIDATE: {subdomain}{Colors.RESET}")
                                print(f"      {Colors.YELLOW}Service: {service}{Colors.RESET}")
                                print(f"      Pattern: {pattern}")
                                print(f"      Status: {response.status_code}")
                                return True
                except:
                    pass
        except:
            pass
        return False
    
    def check_all_takeovers(self):
        print(f"{Colors.CYAN}[+] Checking for subdomain takeovers...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_takeover, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        if not self.takeover_candidates:
            print(f"    {Colors.GREEN}✓ No takeover candidates found{Colors.RESET}")
    
    def detect_api_endpoints(self, subdomain):
        endpoints = set()
        extensions = ['/api/', '/v1/', '/v2/', '/v3/', '/api/v1/', '/api/v2/', '/rest/', '/services/', '/ws/']
        for ext in extensions:
            url = f"http://{subdomain}{ext}"
            try:
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response and response.status_code in [200, 401, 403, 405]:
                    endpoints.add(ext)
                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}API endpoint found: {ext}{Colors.RESET} (Status: {response.status_code})")
            except:
                pass
            
            url = f"https://{subdomain}{ext}"
            try:
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response and response.status_code in [200, 401, 403, 405]:
                    endpoints.add(ext)
                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}API endpoint found: {ext}{Colors.RESET} (Status: {response.status_code})")
            except:
                pass
        return list(endpoints)
    
    def detect_all_api_endpoints(self):
        print(f"{Colors.CYAN}[+] Detecting API endpoints...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.detect_api_endpoints, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    endpoints = future.result()
                    if endpoints:
                        self.api_endpoints[sub] = endpoints
                        self.stats['api_endpoints'] += len(endpoints)
                except:
                    pass
    
    def extract_emails(self, subdomain):
        emails = set()
        try:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response and response.text:
                    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    found = re.findall(pattern, response.text)
                    for email in found:
                        if self.domain in email:
                            emails.add(email)
                            print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}Email found: {email}{Colors.RESET}")
        except:
            pass
        
        txt_records = self.dns_resolve(subdomain, 'TXT')
        if txt_records:
            for record in txt_records:
                if record.startswith('v=spf1'):
                    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    found = re.findall(pattern, record)
                    for email in found:
                        if self.domain in email:
                            emails.add(email)
                            print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}Email found (SPF): {email}{Colors.RESET}")
        
        return list(emails)
    
    def extract_all_emails(self):
        print(f"{Colors.CYAN}[+] Extracting emails...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.extract_emails, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    emails = future.result()
                    if emails:
                        self.emails_found.extend(emails)
                        self.stats['emails_found'] += len(emails)
                except:
                    pass
        if not self.emails_found:
            print(f"    {Colors.YELLOW}⚠ No emails found{Colors.RESET}")
        else:
            print(f"    {Colors.GREEN}✓ Found {len(self.emails_found)} emails{Colors.RESET}")
    
    def scan_ssl(self, subdomain):
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=subdomain)
            conn.settimeout(5)
            conn.connect((subdomain, 443))
            cert = conn.getpeercert()
            ssl_info = {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'notBefore': cert['notBefore'],
                'notAfter': cert['notAfter'],
                'serialNumber': cert['serialNumber'],
                'version': cert.get('version', 'N/A')
            }
            conn.close()
            self.ssl_info[subdomain] = ssl_info
            print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}SSL Certificate found{Colors.RESET}")
            print(f"      Subject: {ssl_info['subject'].get('commonName', 'N/A')}")
            print(f"      Issuer: {ssl_info['issuer'].get('commonName', 'N/A')}")
            print(f"      Valid: {ssl_info['notBefore']} - {ssl_info['notAfter']}")
            return ssl_info
        except:
            return None
    
    def scan_all_ssl(self):
        print(f"{Colors.CYAN}[+] Scanning SSL certificates...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_ssl, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    ssl_info = future.result()
                    if ssl_info:
                        self.ssl_certs[sub] = ssl_info
                        self.stats['ssl_certs'] += 1
                except:
                    pass
    
    def detect_waf(self, subdomain):
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cf-request-id', '__cfduid'],
            'AWS WAF': ['x-amzn-requestid', 'x-amzn-errortype'],
            'Akamai': ['x-akamai-', 'akamai-'],
            'F5 BIG-IP': ['x-wa-info', 'f5-'],
            'ModSecurity': ['x-mod-security', 'mod_security'],
            'Sucuri': ['x-sucuri-', 'sucuri-'],
            'Imperva': ['x-imperva', 'incapsula'],
            'Barracuda': ['x-barracuda', 'barracuda'],
            'Fortinet': ['x-fortinet', 'fortigate'],
            'Palo Alto': ['x-pan-', 'paloalto'],
            'Nginx': ['nginx', 'nginx-waf'],
            'Wordfence': ['wordfence', 'wf-']
        }
        
        detected = []
        try:
            url = f"http://{subdomain}"
            response = self.safe_request(url, max_retries=1, timeout=3)
            if response:
                headers = response.headers
                for waf, signatures in waf_signatures.items():
                    for sig in signatures:
                        if any(sig.lower() in str(k).lower() for k in headers.keys()) or \
                           any(sig.lower() in str(v).lower() for v in headers.values()):
                            detected.append(waf)
                            print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.YELLOW}WAF Detected: {waf}{Colors.RESET}")
                            break
        except:
            pass
        
        return detected
    
    def detect_all_waf(self):
        print(f"{Colors.CYAN}[+] Detecting WAFs...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.detect_waf, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    waf = future.result()
                    if waf:
                        self.waf_info[sub] = waf
                        self.stats['waf_detected'] += len(waf)
                except:
                    pass
    
    def discover_hidden_paths(self, subdomain):
        paths = []
        common_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin', '/cpanel', '/webmail',
                       '/backup', '/backups', '/config', '/conf', '/hidden', '/secret', '/private', '/internal',
                       '/debug', '/test', '/dev', '/staging', '/old', '/backup.zip', '/backup.tar.gz',
                       '/.git', '/.svn', '/.env', '/.htaccess', '/robots.txt', '/sitemap.xml']
        
        for path in common_paths:
            url = f"http://{subdomain}{path}"
            try:
                response = self.safe_request(url, max_retries=1, timeout=2)
                if response and response.status_code in [200, 403, 401]:
                    paths.append({'path': path, 'status': response.status_code})
                    self.stats['hidden_paths_found'] += 1
                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.YELLOW}Hidden path found: {path}{Colors.RESET} (Status: {response.status_code})")
                    
                    if '.git' in path:
                        self.git_repos[subdomain] = url
                        self.stats['git_repos'] += 1
                    if 'backup' in path:
                        self.backup_files[subdomain] = url
                        self.stats['backup_files'] += 1
            except:
                pass
            
            url = f"https://{subdomain}{path}"
            try:
                response = self.safe_request(url, max_retries=1, timeout=2)
                if response and response.status_code in [200, 403, 401]:
                    paths.append({'path': path, 'status': response.status_code})
                    self.stats['hidden_paths_found'] += 1
                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.YELLOW}Hidden path found: {path}{Colors.RESET} (Status: {response.status_code})")
                    
                    if '.git' in path:
                        self.git_repos[subdomain] = url
                        self.stats['git_repos'] += 1
                    if 'backup' in path:
                        self.backup_files[subdomain] = url
                        self.stats['backup_files'] += 1
            except:
                pass
        
        return paths
    
    def discover_all_hidden_paths(self):
        print(f"{Colors.CYAN}[+] Discovering hidden paths...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.discover_hidden_paths, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    paths = future.result()
                    if paths:
                        self.hidden_paths[sub] = paths
                except:
                    pass
    
    def scan_vulnerabilities(self, subdomain):
        vulns = []
        
        try:
            payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', '<img src=x onerror=alert(1)>']
            for payload in payloads:
                url = f"http://{subdomain}/?test={payload}"
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response and payload in response.text:
                    vuln = {'type': 'XSS', 'severity': 'Medium', 'url': url, 'payload': payload}
                    vulns.append(vuln)
                    print(f"    {Colors.RED}⚠ {subdomain}: XSS Vulnerability found{Colors.RESET}")
                    print(f"      URL: {url}")
                    print(f"      Payload: {payload}")
                    break
        except:
            pass
        
        try:
            payloads = ["' OR '1'='1", "' UNION SELECT 1--", "' OR 1=1--"]
            for payload in payloads:
                url = f"http://{subdomain}/?id={payload}"
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response and ('sql' in response.text.lower() or 'mysql' in response.text.lower()):
                    vuln = {'type': 'SQL Injection', 'severity': 'Critical', 'url': url, 'payload': payload}
                    vulns.append(vuln)
                    print(f"    {Colors.RED}⚠ {subdomain}: SQL Injection Vulnerability found{Colors.RESET}")
                    print(f"      URL: {url}")
                    print(f"      Payload: {payload}")
                    break
        except:
            pass
        
        try:
            response = self.safe_request(f"http://{subdomain}", max_retries=1, timeout=3)
            if response:
                headers = response.headers
                missing_headers = []
                security_headers = {}
                
                if 'X-Frame-Options' not in headers:
                    missing_headers.append('X-Frame-Options')
                else:
                    security_headers['X-Frame-Options'] = headers['X-Frame-Options']
                
                if 'X-Content-Type-Options' not in headers:
                    missing_headers.append('X-Content-Type-Options')
                else:
                    security_headers['X-Content-Type-Options'] = headers['X-Content-Type-Options']
                
                if 'Strict-Transport-Security' not in headers:
                    missing_headers.append('HSTS')
                else:
                    security_headers['Strict-Transport-Security'] = headers['Strict-Transport-Security']
                    self.hsts_info[subdomain] = headers['Strict-Transport-Security']
                
                if 'Content-Security-Policy' not in headers:
                    missing_headers.append('CSP')
                else:
                    security_headers['Content-Security-Policy'] = headers['Content-Security-Policy']
                    self.csp_reports[subdomain] = headers['Content-Security-Policy']
                
                if 'Feature-Policy' in headers:
                    self.feature_policy[subdomain] = headers['Feature-Policy']
                if 'Permissions-Policy' in headers:
                    self.permissions_policy[subdomain] = headers['Permissions-Policy']
                
                if 'Access-Control-Allow-Origin' in headers:
                    self.cors_headers[subdomain] = headers['Access-Control-Allow-Origin']
                    if headers['Access-Control-Allow-Origin'] == '*':
                        print(f"    {Colors.RED}⚠ {subdomain}: Wildcard CORS header found{Colors.RESET}")
                
                self.headers[subdomain] = security_headers
                
                if missing_headers:
                    vuln = {'type': 'Missing Security Headers', 'severity': 'Medium', 'headers': missing_headers}
                    vulns.append(vuln)
                    print(f"    {Colors.YELLOW}⚠ {subdomain}: Missing Security Headers{Colors.RESET}")
                    print(f"      Missing: {', '.join(missing_headers)}")
        except:
            pass
        
        return vulns
    
    def scan_all_vulnerabilities(self):
        print(f"{Colors.CYAN}[+] Scanning for vulnerabilities...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_vulnerabilities, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    vulns = future.result()
                    if vulns:
                        self.vulnerabilities.extend(vulns)
                        self.stats['vulnerabilities'] += len(vulns)
                except:
                    pass
        if not self.vulnerabilities:
            print(f"    {Colors.GREEN}✓ No vulnerabilities found{Colors.RESET}")
    
    def check_email_security(self, domain):
        results = {}
        
        spf_records = self.dns_resolve(domain, 'TXT')
        if spf_records:
            for record in spf_records:
                if record.startswith('v=spf1'):
                    results['SPF'] = {'record': record, 'status': 'FOUND'}
                    if '~all' in record:
                        results['SPF']['warning'] = 'Soft fail (~all) - not strict'
                    elif '-all' in record:
                        results['SPF']['warning'] = 'Hard fail (-all) - strict'
                    elif '+all' in record:
                        results['SPF']['warning'] = 'Permit all (+all) - DANGEROUS'
                    break
            else:
                results['SPF'] = {'status': 'MISSING', 'severity': 'HIGH'}
        else:
            results['SPF'] = {'status': 'MISSING', 'severity': 'HIGH'}
        
        dmarc_records = self.dns_resolve(f'_dmarc.{domain}', 'TXT')
        if dmarc_records:
            for record in dmarc_records:
                if record.startswith('v=DMARC1'):
                    results['DMARC'] = {'record': record, 'status': 'FOUND'}
                    if 'p=reject' in record:
                        results['DMARC']['policy'] = 'reject - strict'
                    elif 'p=quarantine' in record:
                        results['DMARC']['policy'] = 'quarantine - medium'
                    elif 'p=none' in record:
                        results['DMARC']['policy'] = 'none - monitor only'
                    break
            else:
                results['DMARC'] = {'status': 'MISSING', 'severity': 'CRITICAL'}
        else:
            results['DMARC'] = {'status': 'MISSING', 'severity': 'CRITICAL'}
        
        dkim_selectors = ['default', 'google', 'microsoft', 'selector1', 'selector2', 'dkim', 'mail']
        dkim_found = False
        for selector in dkim_selectors:
            dkim_records = self.dns_resolve(f'{selector}._domainkey.{domain}', 'TXT')
            if dkim_records:
                for record in dkim_records:
                    if 'v=DKIM1' in record:
                        dkim_found = True
                        results['DKIM'] = {'record': record, 'status': 'FOUND', 'selector': selector}
                        break
                if dkim_found:
                    break
        if not dkim_found:
            results['DKIM'] = {'status': 'MISSING', 'severity': 'MEDIUM'}
        
        self.email_security = results
        self.email_security_results = results
        return results
    
    def check_all_email_security(self):
        print(f"{Colors.CYAN}[+] Checking email security (SPF, DKIM, DMARC)...{Colors.RESET}")
        results = self.check_email_security(self.domain)
        
        for record_type, info in results.items():
            status = info.get('status', 'UNKNOWN')
            if status == 'FOUND':
                color = Colors.GREEN
                icon = '✓'
            elif status == 'MISSING':
                color = Colors.RED
                icon = '✗'
            else:
                color = Colors.YELLOW
                icon = '?'
            
            print(f"    {color}{icon} {record_type}{Colors.RESET}")
            if 'record' in info:
                print(f"      {Colors.DIM}{info['record'][:80]}{Colors.RESET}")
            if 'warning' in info:
                print(f"      {Colors.YELLOW}⚠ {info['warning']}{Colors.RESET}")
            if 'policy' in info:
                print(f"      Policy: {info['policy']}")
    
    def extract_cookies_headers_redirects(self, subdomain):
        try:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                response = self.safe_request(url, max_retries=1, timeout=3, allow_redirects=False)
                if response:
                    if response.cookies:
                        for cookie in response.cookies:
                            cookie_info = {
                                'name': cookie.name,
                                'value': cookie.value,
                                'secure': cookie.secure,
                                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                                'samesite': cookie.get_nonstandard_attr('SameSite', 'None')
                            }
                            if subdomain not in self.cookies:
                                self.cookies[subdomain] = []
                            self.cookies[subdomain].append(cookie_info)
                            self.stats['cookies'] += 1
                            
                            if not cookie.secure:
                                print(f"    {Colors.YELLOW}⚠ {subdomain}: Cookie {cookie.name} missing Secure flag{Colors.RESET}")
                            if not cookie.has_nonstandard_attr('HttpOnly'):
                                print(f"    {Colors.YELLOW}⚠ {subdomain}: Cookie {cookie.name} missing HttpOnly flag{Colors.RESET}")
                    
                    if response.history:
                        for redirect in response.history:
                            if subdomain not in self.redirects:
                                self.redirects[subdomain] = []
                            self.redirects[subdomain].append({
                                'source': redirect.url,
                                'target': redirect.headers.get('Location', ''),
                                'status': redirect.status_code
                            })
                            self.stats['redirects'] += 1
                    
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        forms = re.findall(r'<form[^>]*>', response.text, re.IGNORECASE)
                        if forms:
                            if subdomain not in self.forms:
                                self.forms[subdomain] = []
                            for form in forms:
                                self.forms[subdomain].append(form)
                                self.stats['forms'] += 1
                        
                        js_files = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if js_files:
                            if subdomain not in self.js_files:
                                self.js_files[subdomain] = []
                            for js in js_files:
                                self.js_files[subdomain].append(js)
                                self.stats['js_files'] += 1
                        
                        css_files = re.findall(r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if css_files:
                            if subdomain not in self.css_files:
                                self.css_files[subdomain] = []
                            for css in css_files:
                                self.css_files[subdomain].append(css)
                                self.stats['css_files'] += 1
                        
                        images = re.findall(r'<img[^>]*src=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if images:
                            if subdomain not in self.images:
                                self.images[subdomain] = []
                            for img in images:
                                self.images[subdomain].append(img)
                                self.stats['images'] += 1
                        
                        favicon = re.findall(r'<link[^>]*rel=["\'](?:icon|shortcut icon)["\'][^>]*href=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if favicon:
                            self.favicons[subdomain] = favicon[0]
                        
                        robots = re.findall(r'<meta[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if robots:
                            self.robots_txt[subdomain] = robots[0]
                        
                        sitemap = re.findall(r'<link[^>]*rel=["\']sitemap["\'][^>]*href=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if sitemap:
                            self.sitemaps[subdomain] = sitemap[0]
                        
                        security_txt = re.findall(r'<meta[^>]*name=["\']security["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
                        if security_txt:
                            self.security_txt[subdomain] = security_txt[0]
                        
                        cors_pattern = r'<meta[^>]*http-equiv=["\']Access-Control-Allow-Origin["\'][^>]*content=["\']([^"\']+)["\'][^>]*>'
                        cors_match = re.search(cors_pattern, response.text, re.IGNORECASE)
                        if cors_match:
                            self.cors_headers[subdomain] = cors_match.group(1)
                        
                        sri_pattern = r'<script[^>]*integrity=["\']([^"\']+)["\'][^>]*>'
                        sri_matches = re.findall(sri_pattern, response.text, re.IGNORECASE)
                        if sri_matches:
                            self.sri_hashes[subdomain] = sri_matches
        except:
            pass
    
    def extract_all_cookies_headers_redirects(self):
        print(f"{Colors.CYAN}[+] Extracting cookies, headers, redirects, JS, CSS, images...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.extract_cookies_headers_redirects, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        
        total_cookies = sum(len(c) for c in self.cookies.values())
        total_redirects = sum(len(r) for r in self.redirects.values())
        total_forms = sum(len(f) for f in self.forms.values())
        total_js = sum(len(j) for j in self.js_files.values())
        total_css = sum(len(c) for c in self.css_files.values())
        total_images = sum(len(i) for i in self.images.values())
        
        print(f"    {Colors.GREEN}✓ Extracted:{Colors.RESET}")
        print(f"      Cookies: {total_cookies}")
        print(f"      Redirects: {total_redirects}")
        print(f"      Forms: {total_forms}")
        print(f"      JS Files: {total_js}")
        print(f"      CSS Files: {total_css}")
        print(f"      Images: {total_images}")
        if self.favicons:
            print(f"      Favicons: {len(self.favicons)}")
        if self.robots_txt:
            print(f"      Robots.txt: {len(self.robots_txt)}")
        if self.sitemaps:
            print(f"      Sitemaps: {len(self.sitemaps)}")
        if self.security_txt:
            print(f"      Security.txt: {len(self.security_txt)}")
        if self.sri_hashes:
            print(f"      SRI Hashes: {len(self.sri_hashes)}")
    
    def test_all_url_types(self, subdomain):
        urls = []
        protocols = ['http', 'https']
        paths = ['/', '/index.html', '/index.php', '/index.asp', '/index.aspx', '/index.jsp',
                '/default.html', '/default.php', '/main.html', '/home.html', '/start.html',
                '/api', '/api/v1', '/api/v2', '/rest', '/services', '/ws', '/graphql',
                '/admin', '/login', '/wp-admin', '/cpanel', '/webmail', '/phpmyadmin',
                '/robots.txt', '/sitemap.xml', '/.well-known', '/.git', '/.env', '/backup',
                '/security.txt', '/.htaccess', '/config.php', '/settings', '/debug']
        
        for protocol in protocols:
            for path in paths:
                url = f"{protocol}://{subdomain}{path}"
                try:
                    response = self.safe_request(url, max_retries=1, timeout=3)
                    if response:
                        url_info = {
                            'url': url,
                            'status': response.status_code,
                            'content_type': response.headers.get('Content-Type', 'unknown'),
                            'length': len(response.content)
                        }
                        urls.append(url_info)
                        print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}URL found: {url}{Colors.RESET} (Status: {response.status_code})")
                except:
                    pass
        
        return urls
    
    def discover_full_urls(self, subdomain):
        urls = []
        extensions = ['/', '/index.html', '/index.php', '/index.asp', '/index.aspx', '/index.jsp',
                     '/default.html', '/default.php', '/main.html', '/home.html', '/start.html']
        
        for ext in extensions:
            url = f"http://{subdomain}{ext}"
            try:
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response:
                    url_info = {
                        'url': url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        'length': len(response.content)
                    }
                    urls.append(url_info)
                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}URL found: {url}{Colors.RESET} (Status: {response.status_code})")
            except:
                pass
            
            url = f"https://{subdomain}{ext}"
            try:
                response = self.safe_request(url, max_retries=1, timeout=3)
                if response:
                    url_info = {
                        'url': url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        'length': len(response.content)
                    }
                    urls.append(url_info)
                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}URL found: {url}{Colors.RESET} (Status: {response.status_code})")
            except:
                pass
        
        return urls
    
    def discover_all_full_urls(self):
        print(f"{Colors.CYAN}[+] Discovering full URLs...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.discover_full_urls, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    urls = future.result()
                    if urls:
                        self.full_urls.extend(urls)
                        self.stats['full_urls'] += len(urls)
                except:
                    pass
    
    def discover_all_url_types(self):
        print(f"{Colors.CYAN}[+] Testing all URL types (all protocols and paths)...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_all_url_types, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    urls = future.result()
                    if urls:
                        self.full_urls.extend(urls)
                        self.stats['full_urls'] += len(urls)
                except:
                    pass
    
    def get_whois_info(self):
        try:
            print(f"{Colors.CYAN}[+] Getting WHOIS information...{Colors.RESET}")
            w = whois.whois(self.domain)
            self.whois_info = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'org': w.org,
                'country': w.country,
                'email': w.email,
                'dnssec': w.dnssec
            }
            print(f"    {Colors.GREEN}Registrar{Colors.RESET}: {w.registrar}")
            print(f"    {Colors.GREEN}Created{Colors.RESET}: {w.creation_date}")
            print(f"    {Colors.GREEN}Expires{Colors.RESET}: {w.expiration_date}")
            print(f"    {Colors.GREEN}Name Servers{Colors.RESET}: {', '.join(w.name_servers) if w.name_servers else 'N/A'}")
            print(f"    {Colors.GREEN}Organization{Colors.RESET}: {w.org}")
            print(f"    {Colors.GREEN}Country{Colors.RESET}: {w.country}")
            print(f"    {Colors.GREEN}DNSSEC{Colors.RESET}: {w.dnssec}")
            return self.whois_info
        except Exception as e:
            print(f"    {Colors.RED}Error getting WHOIS: {e}{Colors.RESET}")
            return None
    
    def detect_cloud_assets(self, subdomain):
        cloud_indicators = {
            'AWS': ['amazonaws.com', 'aws', 's3.', 'cloudfront.net', 'ec2-', 'compute-1', 'us-east-', '.elb.amazonaws.com'],
            'GCP': ['googleapis.com', 'cloud.google.com', 'storage.googleapis.com', 'appspot.com', 'compute.googleapis.com', 'run.app'],
            'Azure': ['azure.com', 'azurewebsites.net', 'cloudapp.net', 'azure-api.net', 'azureedge.net', 'trafficmanager.net'],
            'DigitalOcean': ['digitalocean.com', 'do-', 'droplet', 'nyc'],
            'Heroku': ['herokuapp.com', 'heroku.com', 'herokudns.com'],
            'Vercel': ['vercel.app', 'now.sh'],
            'Netlify': ['netlify.app', 'netlify.com'],
            'Cloudflare': ['cloudflare.com', 'cloudflare.net', 'cf-'],
            'Fastly': ['fastly.net', 'fastly.com'],
            'Akamai': ['akamai.net', 'akamaiedge.net'],
            'Shopify': ['myshopify.com', 'shopify.com'],
            'GitHub': ['github.io', 'github.com']
        }
        
        cloud_ip_ranges = {
            'AWS': ['13.32.0.0/15', '13.224.0.0/14', '13.248.0.0/14', '13.32.0.0/15'],
            'Cloudflare': ['104.16.0.0/13', '104.24.0.0/14'],
            'GCP': ['35.184.0.0/14', '35.188.0.0/14', '34.64.0.0/11'],
            'Azure': ['13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14']
        }
        
        detected = []
        
        try:
            for record_type in ['A', 'AAAA', 'CNAME', 'MX']:
                records = self.dns_resolve(subdomain, record_type)
                if records:
                    for record in records:
                        record_lower = record.lower()
                        for cloud, indicators in cloud_indicators.items():
                            for indicator in indicators:
                                if indicator.lower() in record_lower and cloud not in detected:
                                    detected.append(cloud)
                                    print(f"    {Colors.CYAN}{subdomain}{Colors.RESET} {Colors.GREEN}Cloud asset found: {cloud}{Colors.RESET} ({record_type}: {record})")
        except:
            pass
        
        return list(set(detected))
    
    def detect_all_cloud_assets(self):
        print(f"{Colors.CYAN}[+] Detecting cloud assets...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.detect_cloud_assets, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    cloud = future.result()
                    if cloud:
                        self.cloud_assets[sub] = cloud
                        self.stats['cloud_assets'] += len(cloud)
                except:
                    pass
        if not self.cloud_assets:
            print(f"    {Colors.GREEN}✓ No cloud assets detected{Colors.RESET}")
    
    def get_dns_history(self):
        print(f"{Colors.CYAN}[+] Checking DNS History...{Colors.RESET}")
        try:
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                url = f"https://api.securitytrails.com/v1/history/{self.domain}/{record_type}"
                headers = {'APIKEY': 'demo'}
                response = self.safe_request(url, headers=headers, max_retries=1, timeout=5)
                if response and response.status_code == 200:
                    data = response.json()
                    if data.get('records'):
                        self.all_dns_history[record_type] = data['records']
                        print(f"    {Colors.CYAN}{record_type}{Colors.RESET}: {len(data['records'])} historical records")
                        for record in data['records'][:3]:
                            print(f"      {Colors.DIM}→ {record}{Colors.RESET}")
                        if len(data['records']) > 3:
                            print(f"      {Colors.DIM}... and {len(data['records']) - 3} more{Colors.RESET}")
            if not self.all_dns_history:
                print(f"    {Colors.YELLOW}⚠ No DNS history found (API key may be limited){Colors.RESET}")
        except:
            print(f"    {Colors.YELLOW}⚠ DNS History API not available (requires SecurityTrails API key){Colors.RESET}")
    
    def scan_all_cves(self):
        print(f"{Colors.CYAN}[+] Scanning for CVEs...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_cves, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        if self.stats['cves'] == 0:
            print(f"    {Colors.GREEN}✓ No CVEs found{Colors.RESET}")
    
    def check_all_exploits(self):
        print(f"{Colors.CYAN}[+] Checking for exploits...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_exploits, sub): sub for sub in self.subdomains}
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        if self.stats['exploits'] == 0:
            print(f"    {Colors.GREEN}✓ No exploits found{Colors.RESET}")
    
    def take_all_screenshots(self):
        print(f"{Colors.CYAN}[+] Taking screenshots...{Colors.RESET}")
        if not SELENIUM_AVAILABLE:
            print(f"    {Colors.YELLOW}⚠ Selenium not available - install: pip install selenium{Colors.RESET}")
            return
        
        count = 0
        for sub in list(self.subdomains)[:20]:
            if self.take_screenshot(sub):
                count += 1
        if count > 0:
            print(f"    {Colors.GREEN}✓ Took {count} screenshots{Colors.RESET}")
        else:
            print(f"    {Colors.YELLOW}⚠ No screenshots taken (Chrome driver issue?){Colors.RESET}")
    
    def run(self):
        print(f"{Colors.GREEN}[+] Starting complete reconnaissance on {Colors.YELLOW}{self.domain}{Colors.RESET}\n")
        
        try:
            print(f"{Colors.BLUE}[1] Subdomain Discovery{Colors.RESET}")
            sources = [
                ('Wayback Machine', self.get_subdomains_wayback),
                ('HackerTarget', self.get_subdomains_hackertarget),
                ('Commonspeak', self.get_subdomains_commonspeak),
            ]
            
            total_found = 0
            for name, func in sources:
                print(f"  {Colors.YELLOW}{name}{Colors.RESET}:")
                try:
                    count = func()
                    total_found += count
                    self.stats['sources'].append(name)
                except:
                    pass
                print()
            
            print(f"{Colors.BLUE}[2] DNS Bruteforce{Colors.RESET}")
            self.dns_bruteforce()
            
            print(f"{Colors.BLUE}[3] Subdomain Permutations{Colors.RESET}")
            self.generate_permutations()
            
            if f"www.{self.domain}" not in self.subdomains:
                self.subdomains.add(f"www.{self.domain}")
                print(f"  {Colors.CYAN}→{Colors.RESET} Added www.{self.domain}")
            
            print(f"\n{Colors.GREEN}[+] Total subdomains discovered: {Colors.YELLOW}{len(self.subdomains)}{Colors.RESET}")
            self.stats['total'] = len(self.subdomains)
            
            if not self.subdomains:
                print(f"{Colors.RED}[!] No subdomains found. Trying basic enumeration...{Colors.RESET}")
                common = ['www', 'mail', 'ftp', 'webmail', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 
                         'imap', 'test', 'ns', 'blog', 'dev', 'admin', 'forum', 'news', 'vpn']
                for sub in common:
                    self.subdomains.add(f"{sub}.{self.domain}")
                    print(f"  {Colors.CYAN}→{Colors.RESET} {sub}.{self.domain}")
                print(f"{Colors.GREEN}[+] Added {len(self.subdomains)} common subdomains{Colors.RESET}")
            
            print(f"\n{Colors.BLUE}[4] Advanced DNS Enumeration{Colors.RESET}")
            self.resolve_all_dns_advanced()
            
            print(f"\n{Colors.BLUE}[5] Zone Transfer Attempt{Colors.RESET}")
            self.zone_transfer_attempt()
            
            print(f"\n{Colors.BLUE}[6] Port Scanning{Colors.RESET}")
            self.scan_all_ports()
            
            print(f"\n{Colors.BLUE}[7] SSL/TLS Scanning{Colors.RESET}")
            self.scan_all_ssl()
            
            print(f"\n{Colors.BLUE}[8] Technology Detection{Colors.RESET}")
            self.detect_all_technologies()
            
            print(f"\n{Colors.BLUE}[9] WAF Detection{Colors.RESET}")
            self.detect_all_waf()
            
            print(f"\n{Colors.BLUE}[10] Subdomain Takeover Check{Colors.RESET}")
            self.check_all_takeovers()
            
            print(f"\n{Colors.BLUE}[11] API Endpoint Discovery{Colors.RESET}")
            self.detect_all_api_endpoints()
            
            print(f"\n{Colors.BLUE}[12] Hidden Path Discovery{Colors.RESET}")
            self.discover_all_hidden_paths()
            
            print(f"\n{Colors.BLUE}[13] Vulnerability Scanning{Colors.RESET}")
            self.scan_all_vulnerabilities()
            
            print(f"\n{Colors.BLUE}[14] CVE Scanning{Colors.RESET}")
            self.scan_all_cves()
            
            print(f"\n{Colors.BLUE}[15] Exploit Checking{Colors.RESET}")
            self.check_all_exploits()
            
            print(f"\n{Colors.BLUE}[16] Email Security Check (SPF, DKIM, DMARC){Colors.RESET}")
            self.check_all_email_security()
            
            print(f"\n{Colors.BLUE}[17] Full URL Discovery{Colors.RESET}")
            self.discover_all_full_urls()
            
            print(f"\n{Colors.BLUE}[18] All URL Types Testing{Colors.RESET}")
            self.discover_all_url_types()
            
            print(f"\n{Colors.BLUE}[19] Extracting Cookies, Headers, Redirects, JS, CSS, Images{Colors.RESET}")
            self.extract_all_cookies_headers_redirects()
            
            print(f"\n{Colors.BLUE}[20] Cloud Assets Detection{Colors.RESET}")
            self.detect_all_cloud_assets()
            
            print(f"\n{Colors.BLUE}[21] Reverse DNS & BGP Information{Colors.RESET}")
            self.get_all_reverse_dns_bgp()
            
            print(f"\n{Colors.BLUE}[22] DNS History Check{Colors.RESET}")
            self.get_dns_history()
            
            print(f"\n{Colors.BLUE}[23] Taking Screenshots{Colors.RESET}")
            self.take_all_screenshots()
            
            print(f"\n{Colors.BLUE}[24] Email Extraction{Colors.RESET}")
            self.extract_all_emails()
            
            print(f"\n{Colors.BLUE}[25] WHOIS Information{Colors.RESET}")
            self.get_whois_info()
            
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error during scan: {e}{Colors.RESET}")
            if self.verbose:
                traceback.print_exc()
        
        self.cleanup()
    
    def generate_report(self):
        elapsed = time.time() - self.start_time
        
        print(f"\n{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.GREEN}║{Colors.YELLOW}                     SCAN COMPLETE                      {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}[+] Summary{Colors.RESET}")
        print(f"{'='*50}")
        print(f"{Colors.GREEN}Domain{Colors.RESET}: {self.domain}")
        print(f"{Colors.GREEN}Time taken{Colors.RESET}: {elapsed:.2f} seconds")
        print(f"{Colors.GREEN}Total subdomains{Colors.RESET}: {len(self.subdomains)}")
        print(f"{Colors.GREEN}Sources used{Colors.RESET}: {', '.join(self.stats['sources'])}")
        
        print(f"\n{Colors.CYAN}[+] Statistics{Colors.RESET}")
        print(f"{'='*50}")
        print(f"{Colors.GREEN}Alive subdomains{Colors.RESET}: {self.stats['alive']}")
        print(f"{Colors.GREEN}DNS records{Colors.RESET}: {self.stats['dns_records']}")
        print(f"{Colors.GREEN}Open ports{Colors.RESET}: {self.stats['ports_found']}")
        print(f"{Colors.GREEN}Technologies{Colors.RESET}: {self.stats['technologies_found']}")
        print(f"{Colors.GREEN}SSL certificates{Colors.RESET}: {self.stats['ssl_certs']}")
        print(f"{Colors.GREEN}WAFs detected{Colors.RESET}: {self.stats['waf_detected']}")
        print(f"{Colors.GREEN}Takeover candidates{Colors.RESET}: {self.stats['takeovers']}")
        print(f"{Colors.GREEN}API endpoints{Colors.RESET}: {self.stats['api_endpoints']}")
        print(f"{Colors.GREEN}Emails found{Colors.RESET}: {self.stats['emails_found']}")
        print(f"{Colors.GREEN}Full URLs{Colors.RESET}: {self.stats['full_urls']}")
        print(f"{Colors.GREEN}Cloud assets{Colors.RESET}: {self.stats['cloud_assets']}")
        print(f"{Colors.GREEN}Vulnerabilities{Colors.RESET}: {self.stats['vulnerabilities']}")
        print(f"{Colors.GREEN}CVEs found{Colors.RESET}: {self.stats['cves']}")
        print(f"{Colors.GREEN}Exploit potentials{Colors.RESET}: {self.stats['exploits']}")
        print(f"{Colors.GREEN}Hidden paths found{Colors.RESET}: {self.stats['hidden_paths_found']}")
        print(f"{Colors.GREEN}Cookies extracted{Colors.RESET}: {self.stats['cookies']}")
        print(f"{Colors.GREEN}Redirects found{Colors.RESET}: {self.stats['redirects']}")
        print(f"{Colors.GREEN}Forms found{Colors.RESET}: {self.stats['forms']}")
        print(f"{Colors.GREEN}JS files found{Colors.RESET}: {self.stats['js_files']}")
        print(f"{Colors.GREEN}CSS files found{Colors.RESET}: {self.stats['css_files']}")
        print(f"{Colors.GREEN}Images found{Colors.RESET}: {self.stats['images']}")
        print(f"{Colors.GREEN}Git repos found{Colors.RESET}: {self.stats['git_repos']}")
        print(f"{Colors.GREEN}Backup files found{Colors.RESET}: {self.stats['backup_files']}")
        print(f"{Colors.GREEN}Wayback URLs retrieved{Colors.RESET}: {self.stats['wayback_urls']}")
        print(f"{Colors.GREEN}Reverse DNS entries{Colors.RESET}: {self.stats['reverse_dns']}")
        print(f"{Colors.GREEN}BGP entries{Colors.RESET}: {self.stats['bgp']}")
        print(f"{Colors.GREEN}Permutations generated{Colors.RESET}: {self.stats['permutations']}")
        if SELENIUM_AVAILABLE:
            print(f"{Colors.GREEN}Screenshots taken{Colors.RESET}: {self.stats['screenshots']}")
        print(f"{Colors.GREEN}Total requests{Colors.RESET}: {self.stats['requests']}")
        print(f"{Colors.GREEN}Errors{Colors.RESET}: {self.stats['errors']}")
        
        if self.subdomains:
            print(f"\n{Colors.CYAN}[+] Detailed Subdomains Found{Colors.RESET}")
            print(f"{'='*50}")
            for sub in sorted(self.subdomains):
                alive_status = "✓" if self.alive.get(sub, False) else "✗"
                print(f"  {Colors.GREEN}→{Colors.RESET} {sub} [{alive_status}]")
                if sub in self.response_times:
                    print(f"    {Colors.DIM}Response Time: {self.response_times[sub]:.2f}s{Colors.RESET}")
                if sub in self.dns_records:
                    for rec_type, values in self.dns_records[sub].items():
                        print(f"    {Colors.DIM}DNS {rec_type}: {', '.join(values)}{Colors.RESET}")
                if sub in self.ports:
                    print(f"    {Colors.DIM}Open Ports: {', '.join(map(str, self.ports[sub]))}{Colors.RESET}")
                if sub in self.technologies:
                    print(f"    {Colors.DIM}Technologies: {', '.join(self.technologies[sub].keys())}{Colors.RESET}")
                if sub in self.waf_info:
                    print(f"    {Colors.DIM}WAF: {', '.join(self.waf_info[sub])}{Colors.RESET}")
                if sub in self.cloud_assets:
                    print(f"    {Colors.DIM}Cloud Assets: {', '.join(self.cloud_assets[sub])}{Colors.RESET}")
                if sub in self.api_endpoints:
                    print(f"    {Colors.DIM}API Endpoints: {', '.join(self.api_endpoints[sub])}{Colors.RESET}")
                if sub in self.hidden_paths:
                    for path in self.hidden_paths[sub]:
                        print(f"    {Colors.DIM}Hidden Path: {path['path']} (Status: {path['status']}){Colors.RESET}")
                if sub in self.js_files:
                    print(f"    {Colors.DIM}JS Files: {len(self.js_files[sub])}{Colors.RESET}")
                    for js in self.js_files[sub][:3]:
                        print(f"      {Colors.DIM}→ {js}{Colors.RESET}")
                    if len(self.js_files[sub]) > 3:
                        print(f"      {Colors.DIM}... and {len(self.js_files[sub]) - 3} more{Colors.RESET}")
                if sub in self.css_files:
                    print(f"    {Colors.DIM}CSS Files: {len(self.css_files[sub])}{Colors.RESET}")
                    for css in self.css_files[sub][:3]:
                        print(f"      {Colors.DIM}→ {css}{Colors.RESET}")
                    if len(self.css_files[sub]) > 3:
                        print(f"      {Colors.DIM}... and {len(self.css_files[sub]) - 3} more{Colors.RESET}")
                if sub in self.cve_results and self.cve_results[sub]:
                    for cve in self.cve_results[sub]:
                        print(f"    {Colors.RED}⚠ CVE: {cve['cve_id']} ({cve['severity']}){Colors.RESET}")
                if sub in self.exploit_results and self.exploit_results[sub]:
                    for exploit in self.exploit_results[sub]:
                        print(f"    {Colors.RED}⚠ Exploit: {exploit['exploit']} ({exploit['severity']}){Colors.RESET}")
                if sub in self.screenshots:
                    print(f"    {Colors.DIM}Screenshot: {self.screenshots[sub]}{Colors.RESET}")
        
        if self.emails_found:
            print(f"\n{Colors.CYAN}[+] Emails Found{Colors.RESET}")
            print(f"{'='*50}")
            for email in set(self.emails_found):
                print(f"  {Colors.GREEN}→{Colors.RESET} {email}")
        
        if self.email_security_results:
            print(f"\n{Colors.CYAN}[+] Email Security Results{Colors.RESET}")
            print(f"{'='*50}")
            for record_type, info in self.email_security_results.items():
                status = info.get('status', 'UNKNOWN')
                if status == 'FOUND':
                    color = Colors.GREEN
                    icon = '✓'
                else:
                    color = Colors.RED
                    icon = '✗'
                print(f"  {color}{icon} {record_type}{Colors.RESET}")
                if 'record' in info:
                    print(f"    {Colors.DIM}{info['record'][:80]}{Colors.RESET}")
                if 'warning' in info:
                    print(f"    {Colors.YELLOW}⚠ {info['warning']}{Colors.RESET}")
                if 'policy' in info:
                    print(f"    Policy: {info['policy']}")
                if status == 'MISSING':
                    severity = info.get('severity', 'UNKNOWN')
                    print(f"    {Colors.RED}⚠ Missing - {severity} severity{Colors.RESET}")
        
        if self.vulnerabilities:
            print(f"\n{Colors.RED}[+] Vulnerabilities Found{Colors.RESET}")
            print(f"{'='*50}")
            for vuln in self.vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                if severity == 'Critical':
                    color = Colors.RED
                elif severity == 'High':
                    color = Colors.ORANGE
                elif severity == 'Medium':
                    color = Colors.YELLOW
                else:
                    color = Colors.GREEN
                print(f"  {color}[{severity}]{Colors.RESET} {vuln.get('type', 'Unknown')}")
                if 'url' in vuln:
                    print(f"    URL: {vuln['url']}")
                if 'payload' in vuln:
                    print(f"    Payload: {vuln['payload']}")
                if 'headers' in vuln:
                    print(f"    Missing Headers: {', '.join(vuln['headers'])}")
        
        if self.takeover_candidates:
            print(f"\n{Colors.RED}[!] Subdomain Takeover Candidates{Colors.RESET}")
            print(f"{'='*50}")
            for candidate in self.takeover_candidates:
                print(f"  {Colors.RED}⚠{Colors.RESET} {candidate['subdomain']}")
                print(f"    URL: {candidate['url']}")
                print(f"    Service: {candidate.get('service', 'Unknown')}")
                print(f"    Pattern: {candidate['pattern']}")
                print(f"    Status: {candidate.get('status', 'N/A')}")
        
        if self.cookies:
            print(f"\n{Colors.CYAN}[+] Cookies Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, cookies in self.cookies.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {len(cookies)} cookies")
                for cookie in cookies:
                    secure = '✓' if cookie.get('secure') else '✗'
                    httponly = '✓' if cookie.get('httponly') else '✗'
                    print(f"    {cookie['name']} = {cookie['value']} (Secure: {secure}, HttpOnly: {httponly}, SameSite: {cookie.get('samesite', 'None')})")
                    if not cookie.get('secure'):
                        print(f"      {Colors.RED}⚠ Missing Secure flag{Colors.RESET}")
                    if not cookie.get('httponly'):
                        print(f"      {Colors.RED}⚠ Missing HttpOnly flag{Colors.RESET}")
        
        if self.redirects:
            print(f"\n{Colors.CYAN}[+] Redirects Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, redirects in self.redirects.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {len(redirects)} redirects")
                for redirect in redirects:
                    print(f"    {redirect['source']} → {redirect['target']} ({redirect['status']})")
        
        if self.forms:
            print(f"\n{Colors.CYAN}[+] Forms Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, forms in self.forms.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {len(forms)} forms")
                for form in forms[:3]:
                    print(f"    {Colors.DIM}→ {form[:100]}{Colors.RESET}")
                if len(forms) > 3:
                    print(f"    {Colors.DIM}... and {len(forms) - 3} more{Colors.RESET}")
        
        if self.hsts_info:
            print(f"\n{Colors.CYAN}[+] HSTS Information{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, hsts in self.hsts_info.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {hsts}")
        
        if self.csp_reports:
            print(f"\n{Colors.CYAN}[+] CSP Headers{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, csp in self.csp_reports.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {csp}")
        
        if self.cors_headers:
            print(f"\n{Colors.CYAN}[+] CORS Headers{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, cors in self.cors_headers.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {cors}")
                if cors == '*':
                    print(f"    {Colors.RED}⚠ Wildcard CORS - potentially dangerous{Colors.RESET}")
        
        if self.git_repos:
            print(f"\n{Colors.YELLOW}[!] Git Repositories Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, url in self.git_repos.items():
                print(f"  {Colors.RED}⚠{Colors.RESET} {subdomain}: {url}")
        
        if self.backup_files:
            print(f"\n{Colors.YELLOW}[!] Backup Files Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, url in self.backup_files.items():
                print(f"  {Colors.RED}⚠{Colors.RESET} {subdomain}: {url}")
        
        if self.geo_info:
            print(f"\n{Colors.CYAN}[+] IP Geolocation{Colors.RESET}")
            print(f"{'='*50}")
            for ip, geo in self.geo_info.items():
                print(f"  {Colors.GREEN}IP:{Colors.RESET} {ip}")
                print(f"    Country: {geo.get('country')}")
                print(f"    City: {geo.get('city')}")
                print(f"    Region: {geo.get('region')}")
                print(f"    ISP: {geo.get('isp')}")
                print(f"    Organization: {geo.get('org')}")
                print(f"    AS: {geo.get('as')}")
                if geo.get('maps_link'):
                    print(f"    Google Maps: {Colors.BLUE}{geo['maps_link']}{Colors.RESET}")
        
        if self.sri_hashes:
            print(f"\n{Colors.CYAN}[+] SRI Hashes Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, hashes in self.sri_hashes.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {len(hashes)} hashes")
                for h in hashes[:3]:
                    print(f"    {Colors.DIM}→ {h[:50]}...{Colors.RESET}")
                if len(hashes) > 3:
                    print(f"    {Colors.DIM}... and {len(hashes) - 3} more{Colors.RESET}")
        
        if self.wayback_urls:
            print(f"\n{Colors.CYAN}[+] Wayback Machine URLs Retrieved{Colors.RESET}")
            print(f"{'='*50}")
            print(f"  Total URLs: {len(self.wayback_urls)}")
            for url in self.wayback_urls[:10]:
                print(f"    {Colors.DIM}{url}{Colors.RESET}")
            if len(self.wayback_urls) > 10:
                print(f"    {Colors.DIM}... and {len(self.wayback_urls) - 10} more{Colors.RESET}")
        
        if self.feature_policy:
            print(f"\n{Colors.CYAN}[+] Feature Policy Headers{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, policy in self.feature_policy.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {policy}")
        
        if self.permissions_policy:
            print(f"\n{Colors.CYAN}[+] Permissions Policy Headers{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, policy in self.permissions_policy.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {policy}")
        
        if self.favicons:
            print(f"\n{Colors.CYAN}[+] Favicons Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, favicon in self.favicons.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {favicon}")
        
        if self.robots_txt:
            print(f"\n{Colors.CYAN}[+] Robots.txt Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, robots in self.robots_txt.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {robots}")
        
        if self.sitemaps:
            print(f"\n{Colors.CYAN}[+] Sitemaps Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, sitemap in self.sitemaps.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {sitemap}")
        
        if self.security_txt:
            print(f"\n{Colors.CYAN}[+] Security.txt Found{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, security in self.security_txt.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}: {security}")
        
        if self.dnssec_info:
            print(f"\n{Colors.CYAN}[+] DNSSEC Information{Colors.RESET}")
            print(f"{'='*50}")
            for domain, info in self.dnssec_info.items():
                print(f"  {Colors.GREEN}{domain}{Colors.RESET}: {info.get('has_dnssec', False)}")
                if 'records' in info:
                    for record in info['records'][:3]:
                        print(f"    {Colors.DIM}→ {record}{Colors.RESET}")
                    if len(info['records']) > 3:
                        print(f"    {Colors.DIM}... and {len(info['records']) - 3} more{Colors.RESET}")
        
        if self.caa_records:
            print(f"\n{Colors.CYAN}[+] CAA Records{Colors.RESET}")
            print(f"{'='*50}")
            for domain, caa in self.caa_records.items():
                print(f"  {Colors.GREEN}{domain}{Colors.RESET}:")
                for record in caa:
                    print(f"    {Colors.DIM}→ {record}{Colors.RESET}")
        
        if self.asn_info:
            print(f"\n{Colors.CYAN}[+] ASN Information{Colors.RESET}")
            print(f"{'='*50}")
            for ip, info in self.asn_info.items():
                print(f"  {Colors.GREEN}IP:{Colors.RESET} {ip}")
                print(f"    ASN: {info.get('asn', 'N/A')}")
                print(f"    Organization: {info.get('org', 'N/A')}")
                print(f"    Country: {info.get('country', 'N/A')}")
        
        if self.reverse_dns:
            print(f"\n{Colors.CYAN}[+] Reverse DNS (PTR Records){Colors.RESET}")
            print(f"{'='*50}")
            for ip, ptrs in self.reverse_dns.items():
                print(f"  {Colors.GREEN}{ip}{Colors.RESET} → {', '.join(ptrs)}")
        
        if self.bgp_info:
            print(f"\n{Colors.CYAN}[+] BGP Information{Colors.RESET}")
            print(f"{'='*50}")
            for ip, bgp in self.bgp_info.items():
                print(f"  {Colors.GREEN}IP:{Colors.RESET} {ip}")
                print(f"    ASN: {bgp.get('asn', 'N/A')}")
                print(f"    AS Name: {bgp.get('asn_name', 'N/A')}")
                print(f"    Prefix: {bgp.get('prefix', 'N/A')}")
                print(f"    Country: {bgp.get('country', 'N/A')}")
        
        if self.zone_transfer_results:
            print(f"\n{Colors.CYAN}[+] Zone Transfer Results{Colors.RESET}")
            print(f"{'='*50}")
            for ns, records in self.zone_transfer_results.items():
                print(f"  {Colors.GREEN}NS:{Colors.RESET} {ns} ({len(records)} records)")
                for record in records[:10]:
                    print(f"    {Colors.DIM}{record['name']} {record['type']} → {record['value']}{Colors.RESET}")
                if len(records) > 10:
                    print(f"    {Colors.DIM}... and {len(records) - 10} more{Colors.RESET}")
        
        if self.all_dns_history:
            print(f"\n{Colors.CYAN}[+] DNS History{Colors.RESET}")
            print(f"{'='*50}")
            for record_type, records in self.all_dns_history.items():
                print(f"  {Colors.GREEN}{record_type}{Colors.RESET}: {len(records)} historical records")
                for record in records[:5]:
                    print(f"    {Colors.DIM}→ {record}{Colors.RESET}")
                if len(records) > 5:
                    print(f"    {Colors.DIM}... and {len(records) - 5} more{Colors.RESET}")
        
        if self.ssl_info:
            print(f"\n{Colors.CYAN}[+] SSL Information{Colors.RESET}")
            print(f"{'='*50}")
            for subdomain, ssl in self.ssl_info.items():
                print(f"  {Colors.GREEN}{subdomain}{Colors.RESET}")
                print(f"    Subject: {ssl.get('subject', {}).get('commonName', 'N/A')}")
                print(f"    Issuer: {ssl.get('issuer', {}).get('commonName', 'N/A')}")
                print(f"    Valid: {ssl.get('notBefore', 'N/A')} - {ssl.get('notAfter', 'N/A')}")
        
        if self.server_info:
            print(f"\n{Colors.CYAN}[+] Server Information{Colors.RESET}")
            print(f"{'='*50}")
            for url, server in self.server_info.items():
                print(f"  {Colors.GREEN}{url}{Colors.RESET}: {server}")
        
        print(f"\n{Colors.GREEN}[+] Database saved to: {Colors.YELLOW}{self.db_path}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Report generated successfully{Colors.RESET}")
    
    def cleanup(self):
        try:
            self.conn.close()
        except:
            pass
    
    def lock_and_redirect(self):
        CYAN = Colors.CYAN
        RESET = Colors.RESET
        BOLD = Colors.BOLD
        MAGENTA = Colors.MAGENTA
        YELLOW = Colors.YELLOW
        GREEN = Colors.GREEN
        
        print(f"{CYAN}📱 Follow My Instagram: @shv.cyberlab{RESET}")
        print(f"{CYAN}Redirecting to Instagram...{RESET}\n")
        time.sleep(1)
        
        for i in range(5, 0, -1):
            sys.stdout.write(f"\r{BOLD}{MAGENTA}⏳ Redirecting in: {i}...{RESET}")
            sys.stdout.flush()
            time.sleep(1)
        print("\n")
        
        url = "https://instagram.com/shv.cyberlab"
        instagram_pkg = "com.instagram.android"
        
        try:
            if sys.platform == "linux" and "com.termux" in os.environ.get("PREFIX", ""):
                try:
                    subprocess.run(["termux-open", url], timeout=7, capture_output=True)
                    return
                except:
                    pass
                
                try:
                    subprocess.Popen([
                        "am", "start",
                        "-a", "android.intent.action.VIEW",
                        "-d", url,
                        "-p", instagram_pkg
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(1)
                    return
                except:
                    pass
                
                try:
                    subprocess.Popen([
                        "am", "start",
                        "-a", "android.intent.action.VIEW",
                        "-d", url
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return
                except:
                    pass
                
                try:
                    subprocess.run(["termux-open-url", url], timeout=7, capture_output=True)
                    return
                except:
                    pass
                
                try:
                    subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return
                except:
                    pass
                
                print(f"\n{YELLOW}⚠️ Could not open automatically. Open this URL manually:{RESET}")
                print(f"{GREEN}https://instagram.com/shv.cyberlab{RESET}")
                
            elif sys.platform == "win32":
                try:
                    os.system(f"start {url}")
                except:
                    os.system(f"start microsoft-edge:{url}")
            else:
                try:
                    subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
        except Exception as e:
            print(f"{YELLOW}⚠️ Could not open Instagram automatically{RESET}")
            print(f"{GREEN}🔗 Manual link: https://instagram.com/shv.cyberlab{RESET}")

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python suboracle.py <domain> [threads] [timeout]{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python suboracle.py example.com 30 15{Colors.RESET}")
        sys.exit(1)
    
    domain = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 15
    
    scanner = Scanner(domain, threads, timeout)
    scanner.run()
    scanner.lock_and_redirect()

if __name__ == "__main__":
    main()
