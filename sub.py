import dns.resolver
import requests
import concurrent.futures
import argparse
import csv
import logging
import asyncio
import aiohttp
import yaml
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration
with open('config.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)

SIGNATURES = config['takeover_signatures']
DEFAULT_DNS_SERVERS = config['default_dns_servers']

async def check_subdomain(session, subdomain, dns_servers):
    results = {
        'subdomain': subdomain,
        'cname': None,
        'resolves': False,
        'http_status': None,
        'https_status': None,
        'vulnerable': False,
        'notes': []
    }
    
    try:
        # Use custom DNS resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = dns_servers

        # Attempt to resolve the CNAME record
        answers = await asyncio.to_thread(resolver.resolve, subdomain, 'CNAME')
        results['cname'] = str(answers[0].target)
        
        # Check if the CNAME target resolves
        try:
            await asyncio.to_thread(resolver.resolve, results['cname'], 'A')
            results['resolves'] = True
        except dns.resolver.NXDOMAIN:
            results['notes'].append("CNAME does not resolve")
            results['vulnerable'] = True
        
        # Check HTTP and HTTPS
        for protocol in ['http', 'https']:
            try:
                async with session.get(f"{protocol}://{subdomain}", timeout=5, allow_redirects=False) as response:
                    results[f'{protocol}_status'] = response.status
                    if response.status in [404, 503]:
                        results['notes'].append(f"{protocol.upper()} returns {response.status}")
                        results['vulnerable'] = True
                    
                    # Check for takeover signatures
                    if response.status == 200:
                        content = await response.text()
                        for sig in SIGNATURES:
                            if sig.lower() in content.lower():
                                results['notes'].append(f"Possible takeover: '{sig}' found in response")
                                results['vulnerable'] = True
                    
                    # Check HTTPS certificate
                    if protocol == 'https':
                        cert = await session.get_peer_cert(f"{protocol}://{subdomain}")
                        if cert:
                            cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                            results['notes'].append(f"SSL/TLS issuer: {cert_obj.issuer}")
            except aiohttp.ClientError as e:
                results[f'{protocol}_status'] = str(e)
    
    except dns.resolver.NoAnswer:
        results['notes'].append("No CNAME record found")
    except dns.resolver.NXDOMAIN:
        results['notes'].append("Subdomain does not exist")
    except Exception as e:
        results['notes'].append(f"Error: {str(e)}")
    
    return results

async def process_subdomains(subdomains, output_file, dns_servers):
    async with aiohttp.ClientSession() as session:
        tasks = [check_subdomain(session, subdomain, dns_servers) for subdomain in subdomains]
        results = await asyncio.gather(*tasks)
    
    # Write results to CSV
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['subdomain', 'cname', 'resolves', 'http_status', 'https_status', 'vulnerable', 'notes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            result['notes'] = '; '.join(result['notes'])  # Join notes into a single string
            writer.writerow(result)
    
    logger.info(f"Results written to {output_file}")

async def main():
    parser = argparse.ArgumentParser(description="Detect dangling CNAME and subdomain takeover vulnerabilities.")
    parser.add_argument('-i', '--input', required=True, help="Input file containing list of subdomains")
    parser.add_argument('-o', '--output', default='results.csv', help="Output CSV file (default: results.csv)")
    parser.add_argument('-d', '--dns', nargs='+', default=DEFAULT_DNS_SERVERS, help="Custom DNS servers to use")
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    
    await process_subdomains(subdomains, args.output, args.dns)

if __name__ == "__main__":
    asyncio.run(main())
