// Function to base64 encode URL
function base64Encode(url) {
    return btoa(url).replace(/=+$/, '');
}

// Function to process URL
async function processUrl(apiKey, url) {
    const id = base64Encode(url);
    console.log(`URL ID: ${id}`);

    // Send the URL to VirusTotal for analysis and parse the response
    let response;
    try {
        response = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
            headers: { 'x-apikey': apiKey }
        });
        response = await response.json();
    } catch (error) {
        console.error(`Failed to send request to VirusTotal for URL: ${url}`);
        return null;
    }

    // Check if response and response.data are not undefined
    if (!response || !response.data || !response.data.attributes) {
        console.error('Unexpected response from VirusTotal:', response);
        return null;
    }

    const data = response.data.attributes;
    const sha256 = data.last_http_response_content_sha256;
    let crowdsourcedSeverity = null;
    if (data.crowdsourced_context && data.crowdsourced_context[0]) {
        crowdsourcedSeverity = data.crowdsourced_context[0].severity || null;
    }
    const lastAnalysisStats = data.last_analysis_stats;

    // Send the SHA256 hash to VirusTotal for analysis and parse the response
    let response2;
    try {
        response2 = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
            headers: { 'x-apikey': apiKey }
        });
        response2 = await response2.json();
    } catch (error) {
        console.error(`Failed to send request to VirusTotal for SHA256: ${sha256}`);
        return null;
    }

    // Check if response2 and response2.data are not undefined
    if (!response2 || !response2.data || !response2.data.attributes) {
        console.error('Unexpected response from VirusTotal:', response2);
        return null;
    }

    const data2 = response2.data.attributes;
    const lastAnalysisStats2 = data2.last_analysis_stats;
    let popularThreatCategory = null;
    let suggestedThreatLabel = null;
    if (data2.popular_threat_classification) {
        popularThreatCategory = data2.popular_threat_classification.popular_threat_category || null;
        suggestedThreatLabel = data2.popular_threat_classification.suggested_threat_label || null;
    }

    if ((lastAnalysisStats2.malicious + lastAnalysisStats2.suspicious) > (lastAnalysisStats.malicious + lastAnalysisStats.suspicious)) {
        Object.assign(lastAnalysisStats, lastAnalysisStats2);
    }

    let lastAnalysisSum = Object.values(lastAnalysisStats).reduce((a, b) => a + b, 0);

    return {
        detectedURL: url,
        payloadSHA256: sha256,
        crowdsourcedSeverity: crowdsourcedSeverity,
        lastAnalysisStats: lastAnalysisStats,
        lastAnalysisSum: lastAnalysisSum,
        popularThreatCategory: popularThreatCategory,
        suggestedThreatLabel: suggestedThreatLabel
    };
}

window.processUrl = processUrl;
