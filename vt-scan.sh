#!/bin/bash
if [ -z "$1" ] || [ -z "$2" ]
then
    echo "Usage: ./vt-scan.sh [API_KEY] [JSON_TO_ANALYSE]"
    exit 1
fi
# Your VirusTotal API Key
API_KEY=$1
INPUT_FILE=$2

URLS=$(jq -r '.[] | select(.isShady == "Yes") | .detectedURL' $INPUT_FILE | head -n 500)

# Check if metrics.json exists and create a new file with a suffix if it does
FILE="metrics_top10k.json"
if [[ -e $FILE ]] ; then
    i=0
    while [[ -e $FILE ]] ; do
        let i++
        FILE="metrics_top10k_${i}.json"
    done
fi

# Initialize an empty JSON array
echo "[]" > $FILE
# Loop over the URLs
echo "$URLS" | while IFS= read -r URL
do
    # Compute the URL ID
    ID=$(echo -n "$URL" | base64 -w 0 | tr -d '=')
    echo "URL ID: $ID"
    
    # Send the URL to VirusTotal for analysis and parse the response
    RESPONSE=$(curl --silent --request GET \
        --url "https://www.virustotal.com/api/v3/urls/$ID" \
        --header "x-apikey: $API_KEY")
    

    # Check if curl command succeeded
    if [ $? -ne 0 ]
    then
        echo "Failed to send request to VirusTotal for URL: $URL"
        continue
    fi

    # Extract the required fields, it requires jq to be installed!!
    SHA256=$(echo $RESPONSE | jq -r '.data.attributes.last_http_response_content_sha256')
    CROWDSOURCED_SEVERITY=$(echo $RESPONSE | jq -r '.data.attributes.crowdsourced_context[0].severity')
    LAST_ANALYSIS_MALICIOUS=$(echo $RESPONSE | jq -r '.data.attributes.last_analysis_stats.malicious')
    LAST_ANALYSIS_SUSPICIOUS=$(echo $RESPONSE | jq -r '.data.attributes.last_analysis_stats.suspicious')
    LAST_ANALYSIS_UNDETECTED=$(echo $RESPONSE | jq -r '.data.attributes.last_analysis_stats.undetected')
    LAST_ANALYSIS_HARMLESS=$(echo $RESPONSE | jq -r '.data.attributes.last_analysis_stats.harmless')
    LAST_ANALYSIS_TIMEOUT=$(echo $RESPONSE | jq -r '.data.attributes.last_analysis_stats.timeout')

    # Send the SHA256 hash to VirusTotal for analysis and parse the response
    RESPONSE2=$(curl --silent --request GET \
        --url "https://www.virustotal.com/api/v3/files/$SHA256" \
        --header "x-apikey: $API_KEY")

 
    # Extract the required fields from the second response
    LAST_ANALYSIS_MALICIOUS2=$(echo $RESPONSE2 | jq -r '.data.attributes.last_analysis_stats.malicious')
    LAST_ANALYSIS_SUSPICIOUS2=$(echo $RESPONSE2 | jq -r '.data.attributes.last_analysis_stats.suspicious')
    LAST_ANALYSIS_UNDETECTED2=$(echo $RESPONSE2 | jq -r '.data.attributes.last_analysis_stats.undetected')
    LAST_ANALYSIS_HARMLESS2=$(echo $RESPONSE2| jq -r '.data.attributes.last_analysis_stats.harmless')
    LAST_ANALYSIS_TIMEOUT2=$(echo $RESPONSE2 | jq -r '.data.attributes.last_analysis_stats.timeout')
    LAST_ANALYSIS_FAILURE2=$(echo $RESPONSE2 | jq -r '.data.attributes.last_analysis_stats.timeout')
    LAST_ANALYSIS_TYPE_UNSUPPORTED2=$(echo $RESPONSE2 | jq -r '.data.attributes.last_analysis_stats."type-unsupported"')
    # Compute the sum, to be able to calculate scores/weights for criteria/metrics
    LAST_ANALYSIS_SUM=$((LAST_ANALYSIS_MALICIOUS + LAST_ANALYSIS_SUSPICIOUS + LAST_ANALYSIS_UNDETECTED + LAST_ANALYSIS_HARMLESS + LAST_ANALYSIS_TIMEOUT))
    LAST_ANALYSIS_SUM2=$((LAST_ANALYSIS_MALICIOUS2 + LAST_ANALYSIS_SUSPICIOUS2 + LAST_ANALYSIS_UNDETECTED2 + LAST_ANALYSIS_HARMLESS2 + LAST_ANALYSIS_TIMEOUT2 + LAST_ANALYSIS_FAILURE2 + LAST_ANALYSIS_TYPE_UNSUPPORTED2))
    
    POPULAR_THREAT_CATEGORY=$(echo "$RESPONSE2" | jq -r '.data.attributes.popular_threat_classification.popular_threat_category[]')
    SUGGESTED_THREAT_LABEL=$(echo "$RESPONSE2" | jq -r '.data.attributes.popular_threat_classification.suggested_threat_label')

    # Check if jq commands succeeded
    if [ $? -ne 0 ]
    then
        echo "Failed to extract fields from response for URL: $URL"
        continue
    fi

    # Print the extracted fields
    echo "URL: $URL"

    if (((LAST_ANALYSIS_MALICIOUS2 + LAST_ANALYSIS_SUSPICIOUS2) > (LAST_ANALYSIS_MALICIOUS + LAST_ANALYSIS_SUSPICIOUS))); then
        LAST_ANALYSIS_MALICIOUS=$LAST_ANALYSIS_MALICIOUS2
        LAST_ANALYSIS_SUSPICIOUS=$LAST_ANALYSIS_SUSPICIOUS2
        LAST_ANALYSIS_UNDETECTED=$LAST_ANALYSIS_UNDETECTED2
        LAST_ANALYSIS_HARMLESS=$LAST_ANALYSIS_HARMLESS2
        LAST_ANALYSIS_TIMEOUT=$LAST_ANALYSIS_TIMEOUT2
        LAST_ANALYSIS_FAILURE=$LAST_ANALYSIS_FAILURE2
        LAST_ANALYSIS_TYPE_UNSUPPORTED=$LAST_ANALYSIS_TYPE_UNSUPPORTED2
        LAST_ANALYSIS_SUM=$LAST_ANALYSIS_SUM2
    fi

# Create a JSON object for the URL
if [ "$CROWDSOURCED_SEVERITY" = null ] && [ "$LAST_ANALYSIS_MALICIOUS" = null ] && [ "$LAST_ANALYSIS_SUSPICIOUS" = null ] && [ "$LAST_ANALYSIS_UNDETECTED" = null ] && [ "$LAST_ANALYSIS_HARMLESS" = null ]; then
    JSON_OBJECT=$(jq -n --arg url "$URL" --arg hash "$SHA256" '{VirusTotal: {detectedURL: $url, PayloadSHA256: $hash, "VT analysis": null}}')
elif (( LAST_ANALYSIS_MALICIOUS > 0 || LAST_ANALYSIS_SUSPICIOUS > 0 )); then
    JSON_OBJECT=$(jq -n --arg url "$URL" --arg hash "$SHA256" --arg severity "$CROWDSOURCED_SEVERITY" --arg malicious "$LAST_ANALYSIS_MALICIOUS" --arg suspicious "$LAST_ANALYSIS_SUSPICIOUS" --arg undetected "$LAST_ANALYSIS_UNDETECTED"  \
        --arg undetected "$LAST_ANALYSIS_UNDETECTED" --arg harmless "$LAST_ANALYSIS_HARMLESS" --arg timeout "$LAST_ANALYSIS_TIMEOUT" --arg failure "$LAST_ANALYSIS_FAILURE" --arg unsupported "$LAST_ANALYSIS_TYPE_UNSUPPORTED" --arg sum "$LAST_ANALYSIS_SUM"\
        --arg popular_threat_category "$POPULAR_THREAT_CATEGORY" --arg suggested_threat_label "$SUGGESTED_THREAT_LABEL" \
        '{VirusTotal: {detectedURL: $url, PayloadSHA256: $hash, attributes: {crowdsourced_context: {severity: $severity}, last_analysis_stats: {malicious: $malicious, suspicious: $suspicious, undetected: $undetected, total_checks: $sum}, popular_threat_classification: {popular_threat_category: $popular_threat_category, suggested_threat_label: $suggested_threat_label}}}}')

    # Append the JSON object to the array in metrics.json
    jq --argjson b "$JSON_OBJECT" '. += [$b]' $FILE > temp.json && mv temp.json $FILE
fi

sleep 15 # Sleep for 15 seconds to avoid rate limiting
done
echo "JSON object saved in: $FILE"
