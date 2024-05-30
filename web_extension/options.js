/*  *Displays detected URLs in the Options page.
    *Creates JSON and TXT files we requested by the user.
    *Communicates with Shodan and AbuseIPDB.  */

// Function to clean up displayed URLs
function cleanupDisplayedUrls() {
    const detectedUrlsList = document.getElementById('detectedUrlsList');
    while (detectedUrlsList.firstChild) {
        detectedUrlsList.removeChild(detectedUrlsList.firstChild);
    }
    browser.storage.local.remove('detected_urls');
}

// Function to retrieve and display detected URLs
function displayDetectedUrls() {
    
    browser.storage.local.get('detected_urls').then((result) => {
    const detectedUrls = result.detected_urls || [];
    const detectedUrlsList = document.getElementById('detectedUrlsList');
    detectedUrls.forEach((urlObj) => {
        const listItem = document.createElement('li');
        listItem.textContent =  `[${urlObj.pageUrl} : "${urlObj.adUrl}"]`;
        detectedUrlsList.appendChild(listItem);
    });
}).catch((error) => {
    console.error('Error retrieving detected URLs:', error);
});
}

//Whitelist comparison functionalities
function compareWhitelist() {
   fetch(browser.runtime.getURL('whitelist.json'))
    .then(response => response.json())
    .then(whitelist => {
        browser.storage.local.set({whitelist: whitelist}).then(() => {
        }).catch((error) => {
            console.log(`Error: ${error}`);
        });

        browser.storage.local.get(['detected_urls', 'whitelist']).then((result) => {
            
            let detected_urls = Array.isArray(result.detected_urls) ? result.detected_urls.map(item => item.adUrl) : [];
            let whitelist = result.whitelist;

            function isMatch(url, whitelist) {
                return whitelist.some(entry => url.includes(entry));
            }

            let shady_urls = detected_urls.filter(url => !isMatch(url, whitelist));

            browser.storage.local.set({shady_urls: shady_urls}).then(() => {
            }).catch((error) => {
                console.log(`Error: ${error}`);
            });
        }).catch((error) => {
            console.log(`Error: ${error}`);
        });
    });
}

function downloadShadyUrls() {
    // Retrieve the shady_urls from the storage to download txt
    browser.storage.local.get('shady_urls').then((result) => {
        const shady_urls = result.shady_urls || [];
        
        const blob = new Blob([shady_urls.join('\n')], {type: 'text/plain'});

        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'shady_urls.txt';

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }).catch((error) => {
        console.log(`Error: ${error}`);
    });
}

/*URLhaus comparison functionalities*/
function compareWithUrlhaus() {
    // Retrieve the shady_urls from the storage
    browser.storage.local.get('shady_urls').then((result) => {
        const shady_urls = result.shady_urls || [];

        // Fetch the data from the URL
        fetch('https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt')
            .then(response => response.text())
            .then(data => {
                // Split the data into lines and filter out the URLs
                const urlhaus_urls = data.split('\n')
                    .filter(line => line.startsWith('||') && line.endsWith('^'))
                    .map(line => line.slice(2, -1));  // Remove the || and ^

                // Compare the shady_urls with the urlhaus_urls
                const common_urls = shady_urls.filter(url => urlhaus_urls.includes(url));
                browser.storage.local.set({common_urls: common_urls}).then(() => {
                }).catch((error) => {
                    console.log(`Error: ${error}`);
                });
            })
            .catch((error) => {
                console.log(`Error: ${error}`);
            });
    }).catch((error) => {
        console.log(`Error: ${error}`);
    });
}


/*****DNS lookup and reverse lookup functionalities****/
async function gatherIpAndShodanData(url, checkIPDB) {
    const extractHostname = (url) => {
        try {
            const urlObject = new URL(url);
            return urlObject.hostname;
        } catch (error) {
            console.error("Invalid URL format:", url);
            return null;
        }
    };

    const fetchReverseDNS = async (ip) => {
        const shodanUrl = `https://internetdb.shodan.io/${ip}`;
        try {
            const response = await fetch(shodanUrl);
            if (response.ok) {
                const data = await response.json();
                return {
                    ip: ip,  
                    hostnames: data.hostnames || [],
                    tags: data.tags || [],
                    cpes: (data.data || []).flatMap(d => d.cpe || [])
                };
            } else {
                console.error(`Failed to retrieve data from Shodan for IP ${ip}: ${response.status}`);
                return { ip, hostnames: [], tags: [], cpes: [] };
            }
        } catch (error) {
            console.error(`HTTP Request to Shodan failed for IP ${ip}: ${error}`);
            return { ip, hostnames: [], tags: [], cpes: [] };
        }
    };

    //Fetch data from AbuseIPDB. If this option is desired, please change the API key (const abuseIpDbApiKey)
    const fetchAbuseIPDBInfo = async (ip, checkIPDB) => {
        
            const abuseIpDbApiKey = 'your_api_key_here';
            const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`;
            const headers = {
                'Key': abuseIpDbApiKey,
                'Accept': 'application/json'
            };

            try {
                const response = await fetch(url, { headers });
                if (response.ok) {
                    const data = await response.json();
                    return data.data;
                } else {
                    console.error(`Failed to retrieve data from AbuseIPDB for IP ${ip}: ${response.status}`);
                    return null;
                }
            } catch (error) {
                console.error(`HTTP Request to AbuseIPDB failed for IP ${ip}: ${error}`);
                return null;
            }
        
    };

    let hostname = extractHostname(url);
    if (!hostname) return { ips: [], shodanResults: [], abuseIpDbResults: [] };

    try {
        const record = await browser.dns.resolve(hostname, ["disable_ipv6"]);
        const ips = record.addresses;
        const results = await Promise.all(ips.map(async (ip) => {
            const shodanData = await fetchReverseDNS(ip);
            const abuseIpDbData = await fetchAbuseIPDBInfo(ip, checkIPDB);
            return {
                ip,
                shodanData,
                abuseIPDBData: abuseIpDbData ? {
                    countryCode: abuseIpDbData.countryCode,
                    isWhitelisted: abuseIpDbData.isWhitelisted,
                    abuseConfidenceScore: abuseIpDbData.abuseConfidenceScore,
                    usageType: abuseIpDbData.usageType
                } : null
            };
        }));

        return {
            ips,
            results
        };
    } catch (error) {
        console.error("Error resolving DNS or fetching data:", error);
        return { ips: [], results: [] };
    }
}


/****JSON export functionalities*, please, include the VirusTotal API key***/
async function generateJSON() {
    compareWhitelist();
    compareWithUrlhaus();
    try {
        // Retrieve the necessary data from the storage
        const result = await browser.storage.local.get(['detected_urls', 'shady_urls', 'common_urls']);
        const detected_urls = result.detected_urls || [];
        const shady_urls = result.shady_urls || [];
        const common_urls = result.common_urls || [];
        let cspHeader = 'No CSP data';
        let cspHeaderValue = 'No CSP data';

        // Gather additional data asynchronously for shady URLs
        const dataPromises = detected_urls.map(async url => {
            const ipData = shady_urls.includes(url.adUrl) ? await gatherIpAndShodanData(url.adUrl, true) : { ips: [], results: [] };
            try {
                const cspData = await browser.storage.local.get(url.adUrl);
                if (cspData[url.adUrl]) {
                    cspHeader = cspData[url.adUrl].cspHeader || 'No CSP data';
                    cspHeaderValue = cspData[url.adUrl].cspHeaderValue || 'No CSP data';
                }
            } catch (error) {
                console.error('Failed to retrieve CSP data for:', url.adUrl, error);
            }
            //Include the VirusTotal API key below
            let virusTotal = null;
            if (shady_urls.includes(url.adUrl)) {
                virusTotal = await processUrl('your_API_key_here', url.adUrl);
            }
            return {
                parentURL: url.pageUrl,
                detectedURL: url.adUrl,
                mdnClassification: url.classification,
                isShady: shady_urls.includes(url.adUrl) ? 'Yes' : 'No',
                isInUrlhaus: common_urls.includes(url.adUrl) ? 'Yes' : 'No',
                ipAddresses: ipData.ips,
                shodanResults: ipData.results.map(r => ({
                    ip: r.ip,
                    hostnames: r.shodanData.hostnames,
                    tags: r.shodanData.tags,
                    cpes: r.shodanData.cpes
                })),
                abuseIPDBData: ipData.results.map(r => r.abuseIPDBData),
                cspHeader: cspHeader,
                cspHeaderValue: cspHeaderValue,
                VirusTotal: virusTotal
            };
        });

        const data = await Promise.all(dataPromises);

        // Calculate summary statistics
        let uniqueParentURLs = new Set(data.map(item => item.parentURL)).size;
        let uniqueDetectedURLs = new Set(data.map(item => item.detectedURL)).size;
        let totalShady = data.filter(item => item.isShady === "Yes").length;
        let totalInUrlhaus = data.filter(item => item.isInUrlhaus === "Yes").length;

        // Calculate most common IP addresses
        let ipCounts = {};
        data.forEach(item => {
            item.ipAddresses.forEach(ip => {
                if (ip in ipCounts) {
                    ipCounts[ip]++;
                } else {
                    ipCounts[ip] = 1;
                }
            });
}       );
        //Taking top3
        let mostCommonIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);

        // Calculate most common domains
        let domainCounts = {};
        data.forEach(item => {
            item.shodanResults.forEach(result => {
                if (result.hostnames) {
                    result.hostnames.forEach(domain => {
                        if (domain in domainCounts) {
                            domainCounts[domain]++;
                        } else {
                            domainCounts[domain] = 1;
                        }
                    });
                }
            });
        });
        //Taking top3
        let mostCommonDomains = Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);

        // Calculate number of ads per parent URL
        let adsPerParentURL = {};
        data.forEach(item => {
            if (item.parentURL in adsPerParentURL) {
                adsPerParentURL[item.parentURL]++;
            } else {
                adsPerParentURL[item.parentURL] = 1;
            }
        });
        let topAdsPerParentURL = Object.entries(adsPerParentURL)
            .filter(([key, value]) => key !== 'undefined')
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        let cspSummary = {};
            data.forEach(item => {
                let cspValue = item.cspHeaderValue;
                if (cspSummary[cspValue]) {
                    cspSummary[cspValue]++;
                } else {
                    cspSummary[cspValue] = 1;
                }
            });

        // Create summary object
        let summary= {
            Summary: {
                totalParentURLs: uniqueParentURLs,
                totalAdDetectedURLs: uniqueDetectedURLs,
                totalShady: totalShady,
                totalInUrlhaus: totalInUrlhaus,
                mostCommonIPs: mostCommonIPs.map(item => ({ [item[0]]: item[1] })),
                mostCommonDomains: mostCommonDomains.map(item => ({ [item[0]]: item[1] })),
                adsPerParentURL: topAdsPerParentURL.map(item => ({ [item[0]]: item[1] })),
                cspSummary: cspSummary
            }
        };

        // Add summary to the beginning of the data
        data.unshift(summary);

        // Convert the data to JSON format
        const json = JSON.stringify(data, null, 2);

        // Create a blob from the JSON string
        const blob = new Blob([json], {type: 'application/json'});

        // Create a link element and set its href to the blob's URL
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'results.json';

        // Append the link to the body, click it, and then remove it
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (error) {
        console.log(`Error: ${error}`);
    }
}

// Call the function to display detected URLs when the options page loads
displayDetectedUrls();

document.getElementById('cleanupButton').addEventListener('click', cleanupDisplayedUrls);
document.getElementById('downloadShady').addEventListener('click', downloadShadyUrls);
document.getElementById('exportJSONOverview').addEventListener('click', generateJSON);