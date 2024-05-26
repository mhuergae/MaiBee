import json
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from matplotlib.patches import Patch
import argparse

parser = argparse.ArgumentParser(description='Plots on results.json. Use approach tags, country, shady or all.')
parser.add_argument('-i', '--input', required=True, help='results JSON file to be plotted')
parser.add_argument('-a', '--approach', required=True, choices=['tags', 'country', 'shady', 'all'], help='Approach to be used')
args = parser.parse_args()

# Function to display the percentage and count in the pie chart
def make_autopct(values):
    def my_autopct(pct):
        total = sum(values)
        val = int(round(pct*total/100.0))
        return '{p:.1f}%  ({v:d})'.format(p=pct,v=val)
    return my_autopct

def plot_spider(categories, values):
    num_vars = len(categories)
    
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    
    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
    categories, values = zip(*sorted(zip(categories, values), key=lambda x: x[1], reverse=True))
    
    values += values[:1]
    angles += angles[:1]

    ax.fill(angles, values, color='red', alpha=0.25)
    ax.plot(angles, values, color='red', linewidth=2)

    ax.set_yticklabels([])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)

    # Create a legend with the counts
    legend_elements = [Patch(facecolor='red', alpha=0.25, label=f'{category}: {count}') for category, count in zip(categories, values[:-1])]
    ax.legend(handles=legend_elements, title="Counts", loc="upper left", bbox_to_anchor=(1.05, 1), borderaxespad=0.)

def plot_top_5_tags(tags, tag_values):
    top_5_tags, tag_values = zip(*sorted(zip(tags, tag_values), key=lambda x: x[1], reverse=True)[:5])
    angles = np.linspace(0, 2 * np.pi, len(top_5_tags), endpoint=False).tolist()
    tag_values += tag_values[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
    ax.fill(angles, tag_values, color='blue', alpha=0.25)
    ax.plot(angles, tag_values, color='blue', linewidth=2)
    ax.set_yticklabels([])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(top_5_tags)
    legend_elements = [Patch(facecolor='blue', alpha=0.25, label=f'{tag}: {count}') for tag, count in zip(top_5_tags, tag_values[:-1])]
    ax.legend(handles=legend_elements, title="Counts", loc="upper left", bbox_to_anchor=(1.05, 1), borderaxespad=0.)

def plot_top_10_countries(countries, country_values):
    top_10_countries, country_values = zip(*sorted(zip(countries, country_values), key=lambda x: x[1], reverse=True)[:10])
    angles = np.linspace(0, 2 * np.pi, len(top_10_countries), endpoint=False).tolist()
    country_values += country_values[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
    ax.fill(angles, country_values, color='blue', alpha=0.25)
    ax.plot(angles, country_values, color='blue', linewidth=2)
    ax.set_yticklabels([])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(top_10_countries)
    legend_elements = [Patch(facecolor='blue', alpha=0.25, label=f'{country}: {count}') for country, count in zip(top_10_countries, country_values[:-1])]
    ax.legend(handles=legend_elements, title="Counts", loc="upper left", bbox_to_anchor=(1.05, 1), borderaxespad=0.)


with open(args.input, 'r') as f:
    data = json.load(f)

if args.approach in ['tags', 'all']:
    # Extract the tags and count their occurrences
    tags = []
    for item in data:
        if 'shodanResults' in item:
            for shodanResults in item['shodanResults']:
                if 'tags' in shodanResults:
                    tags.extend(shodanResults['tags'])

    if not tags:
        print("'shodanResults' field does not exist in the JSON data or no tags found.")
    else:
        counts = Counter(tags)
        # Define the data for the plot
        categories = list(counts.keys())
        values = list(counts.values())
        plot_spider(categories, values)
        plt.title('Top 10k Majestic: Tags Distribution')
        plot_top_5_tags(categories, values)
        plt.title('Top 10k Majestic: Tags Distribution')

if args.approach in ['country', 'all']:
    # Extract the country codes and count their occurrences
    country_codes = []
    for item in data:
        if 'abuseIPDBData' in item:
            for abuseIPDBData in item['abuseIPDBData']:
                country_code = abuseIPDBData.get('countryCode')
                if country_code:
                    country_codes.append(country_code)

    if not country_codes:
        print("'abuseIPDBData' field does not exist in the JSON data, is null, or no country codes found.")
    else:
        plt.figure()
        counts = Counter(country_codes)
        # Define the data for the plot
        categories = list(counts.keys())
        values = list(counts.values())
        plot_spider(categories, values)
        plt.title('Top 10k Majestic: Country distribution')
        plot_top_10_countries(categories, values)
        plt.title('Top 10k Majestic: Country distribution')

if args.approach in ['shady', 'all']:
    # Extract the isShady values and count their occurrences
    is_shady_values = [item['isShady'] for item in data if 'isShady' in item]

    if not is_shady_values:
        print("'isShady' field does not exist in the JSON data.")
    else:
        counts = Counter(is_shady_values)

        # Extract totalAdDetectedURLs and calculate 'No' values
        total_ad_detected_urls = sum(item['Summary']['totalAdDetectedURLs'] for item in data if 'Summary' in item and 'totalAdDetectedURLs' in item['Summary'])
        counts['No'] = total_ad_detected_urls - counts['Yes']

        # Define the data for the plot
        labels = list(counts.keys())
        sizes = list(counts.values())

        # Create the pie chart
        plt.figure()
        colors = [(141/255, 167/255, 220/255), (215/255, 118/255, 163/255)] 
        plt.pie(sizes, labels=labels, colors=colors, autopct=make_autopct(sizes))
        plt.axis('equal')  # Equal aspect ratio ensures the pie chart is circular
        plt.title('Is Shady Distribution')


plt.show()
