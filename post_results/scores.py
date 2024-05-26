import json
import argparse
from typing import List
import ipaddress
from typing import List
import ipaddress
import ipaddress
from collections import Counter, defaultdict

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Aggregate URL scores from multiple JSON files")
parser.add_argument('-i', '--input', nargs='+', required=True, help='Paths to input JSON files')
parser.add_argument('-o', '--output', required=True, help='Path to output JSON file')
args = parser.parse_args()

def calculate_dynamic_score(rating):
    if 0 < rating < 20:
        return 0.2
    elif 20 <= rating < 40:
        return 0.4
    elif 40 <= rating < 60:
        return 0.6
    elif 60 <= rating < 80:
        return 0.8
    elif rating >= 80:
        return 1
    else:
        return 0

def calculate_score(shady_score, urlhaus_score, vt_score, ipdb_score, ip_similarity):
    return shady_score + urlhaus_score + vt_score + ipdb_score + ip_similarity

def classify_ip_using_shodan(ip, shodan_data):
    """Classify IP based on Shodan results."""
    for entry in shodan_data:
        if entry['ip'] == ip:
            if 'cdn' in entry['tags']:
                return 'CDN'
            if 'cloud' in entry['tags']:
                return 'Cloud'
            if 'eol-product' in entry['tags']:
                return 'eol'
            if 'iot' in entry['tags']:
                return 'IoT'
            if 'webcam' in entry['tags']:
                return 'Webcam'
            if 'hosting' in entry['tags']:
                return 'Hosting'
            if 'self-signed' in entry['tags']:
                return 'self-signed'
    return 'Unknown'

def score_ip_suspiciousness(ips, shodan_results):
    score = 0
    criteria = [] 

    if len(ips) <= 1:
        return 0, criteria  # Return 0 and empty criteria if there is 1 or fewer IPs

    # Classify all IPs using Shodan data
    classifications = [classify_ip_using_shodan(ip, shodan_results) for ip in ips]
    class_counter = Counter(classifications)

    # 1. Diversity in IP ranges: Homogeneous or not
    if 'Unknown' not in class_counter and 'self-signed' not in class_counter and len(class_counter) == 1:
        # All IPs from a single class, like all 'CDN' or all 'Cloud'
        score += 0
    elif 'Unknown' in class_counter or 'self-signed' in class_counter:
        score += 2
    else:
        # Mixed types
        score += 1

    # 2. Geographical consistency
    # Use the first octet for a rough estimate of geographic diversity
    first_octets = [ip.split('.')[0] for ip in ips]
    octet_count = defaultdict(int)
    for octet in first_octets:
        octet_count[octet] += 1
    unique_octets = len(octet_count)

    groups = sum(1 for count in octet_count.values() if count > 0)

    # Calculate suspicion score
    if(len(ips) == 2):
            score += 0
    elif groups <= (len(ips) / 2):
            score += 0
    elif unique_octets == len(ips):
              score += 2
    else:
        score += 1

    # 3. Network size
    subnets = {ip.split('.', 1)[0] for ip in ips}
    if(len(ips) == 2):
        score += 0
    elif len(subnets) == len(ips):
        # Many different subnets
        score += 2
    elif len(subnets) < len(ips) / 2:
        score += 0
    else:
        score += 1

    # 4. Adjust scores based on tags indicating less suspicion
    has_cdn = any('cdn' in entry['tags'] for entry in shodan_results)
    has_cloud = any('cloud' in entry['tags'] for entry in shodan_results)
    has_eol = any('eol-product' in entry['tags'] for entry in shodan_results)

    if has_cdn:
        score -= 1
    if has_cloud:
        score -= 1
    if has_eol:
        score += 1 # End-of-life devices are more vulnerable

    # Ensure score is not negative after adjustments
    score = max(score, 0)

    # Normalize the score to be in the range 0-1
    max_score = 7
    final_score = round((score / max_score) * 5) / 5

    return final_score, criteria

# Create a dictionary to store the scores for each URL
scores = {}

# Process each input JSON file
for input_path in args.input:
    with open(input_path) as f:
        data = json.load(f)

    # Iterate over the list of URLs in the current JSON file
    for url_data in data:

        if 'detectedURL' not in url_data:
            continue

        is_shady = url_data.get('isShady', 'No').lower() == 'yes'
        if not is_shady:
            continue

        shady_rating = 1 if is_shady else 0
        urlhaus_rating = 1 if url_data.get('isInUrlhaus', 'No').lower() == 'yes' else 0
        ipdb_rating = 0
        ip_similarity_rating = 0.0 # Default value
        vt_rating = 0  # default value

        if url_data['abuseIPDBData']:
            ipdb_rating = max((int(item['abuseConfidenceScore']) for item in url_data['abuseIPDBData'] if item is not None and 'abuseConfidenceScore' in item), default=0)

        else:
            ipdb_rating = 0

        if url_data['shodanResults']:
            shodanResults = url_data['shodanResults']
        else:
            shodanResults = []

        if url_data['ipAddresses']:
            ip_suspiciousness_rating, criteria = score_ip_suspiciousness(url_data['ipAddresses'], shodanResults)


        if url_data['VirusTotal'] is not None and 'attributes' in url_data['VirusTotal'] and 'last_analysis_stats' in url_data['VirusTotal']['attributes']:
            stats = url_data['VirusTotal']['attributes']['last_analysis_stats']
            malicious = int(stats.get('malicious', 0))
            suspicious = int(stats.get('suspicious', 0))
            undetected = int(stats.get('undetected', 0))
            total_checks = int(stats.get('total_checks', 0))

            # Avoid division by zero
            if total_checks - undetected != 0:
                vt_rating = ((malicious + suspicious) / (total_checks - undetected)) * 100


        shady_score = 15 * shady_rating
        urlhaus_score = 20 * urlhaus_rating
        vt_score = round(40 * calculate_dynamic_score(vt_rating))
        ipdb_score = round(20 * (ipdb_rating/100),2)
        ip_suspiciousness_score = round(5 * ip_suspiciousness_rating, 2)

        total_score = calculate_score(shady_score, urlhaus_score, vt_score, ipdb_score, ip_suspiciousness_score)
        scores[url_data['detectedURL']] = {
            'shady_score': shady_score,
            'urlhaus_score': urlhaus_score,
            'ipdb_score': ipdb_score,
            'vt_score': vt_score,
            'ip_suspiciousness_score': ip_suspiciousness_score,
            'total_score': total_score,
            'criteria': criteria
        }

all_scores = []

# Aggregate the scores dictionary and add the scores to the all_scores list
for url, score in scores.items():
    final_score = score['total_score']
    all_scores.append({
        "adURL": url,
        "shady_score": score.get('shady_score', 0),
        "urlhaus_score": score.get('urlhaus_score', 0),
        "vt_score": score.get('vt_score', 0),
        "ipdb_score": score.get('ipdb_score', 0),
        "ip_suspicion_score": score.get('ip_suspiciousness_score', 0),
        "final_score (%)": final_score
    })
all_scores.sort(key=lambda x: x["final_score (%)"], reverse=True)
# Write the aggregated scores to the output JSON file
with open(args.output, 'w') as f:
    json.dump(all_scores, f, indent=2)
