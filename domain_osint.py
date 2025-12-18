import dns.resolver
import whois
import socket
from ipwhois import IPWhois
import subprocess

def get_dns_records(domain):
  record_types=["A", "MX", "NS", "TXT"]
  dns_data={}

  for record in record_types:
    try:
      answers=dns.resolver.resolve(domain, record)
      dns_data[record]=[str(rdata) for rdata in answers]
    except Exception:
      dns_data[record]=[]

  return dns_data


def get_whois_info(domain):
  try:
    w=whois.whois(domain)
    return{
      "domain_name": w.domain_name,
      "registrar": w.registrar,
      "creation_date": w.creation_date,
      "expiration_date": w.expiration_date,
      "emails": w.emails,
      "name_servers": w.name_servers,
      "country": w.country
    }
  except Exception as e:
    return{"error": str(e)}


def get_ip_info(domain):
  try:
    ip=socket.gethostbyname(domain)
    ip_data={"ip": ip}

    obj=IPWhois(ip)
    rdap=obj.lookup_rdap()

    ip_data["asn"]=rdap.get("asn")
    ip_data["asn_description"]=rdap.get("asn_description")
    ip_data["country"]=rdap.get("network", {}).get("country")
    ip_data["cidr"]=rdap.get("network", {}).get("cidr")

    return ip_data
  except Exception as e:
    return{"error": str(e)}


def find_subdomains_knockpy(domain):
  try:
    print(f"\nRunning Knockpy for subdomain enumeration on: {domain}\n")

    result=subprocess.run(
      [
        "python",
        "knock\\knock\\knockpy.py",
        "-d", domain,
        "--recon",
        "--silent"
      ],
      capture_output=True,
      text=True,
      timeout=300
    )

    # Print Knockpy output directly
    print("Knockpy Output:")
    print(result.stdout)

    # Print errors if any
    if result.stderr:
      print("Knockpy Errors:")
      print(result.stderr)

  except subprocess.TimeoutExpired:
    print("Knockpy timed out")

  except Exception as e:
    print(f"Knockpy error: {e}")


def domain_osint(domain):
  print(f"\nOSINT Report for: {domain}")
  print("=" * 50)

  print("\nDNS Records")
  dns_records=get_dns_records(domain)
  for rtype, records in dns_records.items():
    print(f"{rtype}: {records}")

  print("\nWHOIS Information")
  whois_info=get_whois_info(domain)
  for key, value in whois_info.items():
    print(f"{key}: {value}")

  print("\nIP / Hosting Information")
  ip_info=get_ip_info(domain)
  for key, value in ip_info.items():
    print(f"{key}: {value}")

  subdomains=find_subdomains_knockpy(domain)

  if subdomains:
    print("\nDiscovered Subdomains")
    for sub in subdomains:
      print(f" - {sub}")
  else:
    pass


if __name__=="__main__":
  target_domain=input("Enter domain name: ").strip()
  domain_osint(target_domain)
