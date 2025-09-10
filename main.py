import tldextract
import Levenshtein as lv 

legitimate_domains = ['cisco.com','crowdstrike.com','nist.gov']

test_urls = [

    'https://www.nist.gov/new-events',
    'https://www.cisco.com',
    'https://www.crowdstrike.com',
    'https://www.cisc0.c0m',
    'https://www.cr0wdstrik3.com',
    'https://www.cisc0.net',
    'https://www.nist.net',
    'https://cisco.phishy.com',
    'https://login.crowdstrike.support.com'


]

# Break a URL into subdomain, domain, and suffix
def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix


def is_misspelled_domain(domain, suffix, legitimate_domains, threshold= 0.9):

#  Check if the domain looks like a misspelled version of a legitimate one. Uses Levenshtein similarity ratio (0 = completely different, 1 = identical).
   
    for legit_domain in legitimate_domains:
        legit_name = legit_domain.split('.')[0]

        similarity = max(
            lv.ratio(domain, legit_name),
            lv.ratio(f"{domain}.{suffix}", legit_domain)
        )

        if similarity >= threshold:
            return False # Which the domain is correct and not misspelled 
    return True
    
def has_suspicious_subdomain(subdomain, legitimate_domains):
    if not subdomain:
        return False # no subdomain, nothing to check
    
    for legit_domain in legitimate_domains:
        legit_domain = legit_domain.split('.')[0]
        if legit_domain in subdomain.lower():
            return True
    return False
        
    
def is_phishing_url(url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    # Check if it's a known legitimate domain
    if f"{domain}.{suffix}" in legitimate_domains:
        return False
    
    # Check for misspelled domain names
    if is_misspelled_domain(domain, suffix, legitimate_domains):
        print(f'[ALERT] Potential phishing detected(misspelled domain): {url}')
        return True
    
    # Check for suspicious subdomains
    if has_suspicious_subdomain(subdomain, legitimate_domains):
        print(f'[ALERT] Potential phishing(suspicious subdomain): {url}')
        return True
    
    return False
    







