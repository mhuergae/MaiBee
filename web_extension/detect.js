//Background script: listens for web activity and detects URL patterns - adList
window.setupRequestListener = setupRequestListener;
const regionalLists = [
    ['https://', 'eas', 'ylist.to/', 'eas', 'ylist/', 'eas', 'ylist.txt'].join(''),
    ['https://', 'eas', 'ylist.to/', 'eas', 'ylistgermany/', 'eas', 'ylistgermany.txt'].join(''),
    ['https://', 'eas', 'ylist-downloads.a', 'dblo', 'ckplus.org/', 'eas', 'ylistchina.txt'].join(''),
    ['https://', 'easy', 'l', 'ist-', 'down', 'loads.', 'a', 'd', 'block', 'plus.org/', 'indianlist.txt'].join(''),
    ['https://', 'eas', 'y', 'list-', 'down', 'loads.', 'ad', 'block', 'plus.org/', 'rua', 'dlist.txt'].join('')
];
let urls = [];
initialize().catch(console.error)

async function initialize() {
    console.log('Initializing the ad detector extension');
    urls = await readAndProcessFile(regionalLists);
}

async function readFile(filePath) {
    try {
        console.log('Reading file:', filePath);
        const response = await fetch(filePath);
        const text = await response.text();
        return text; 
    } catch (error) {
        console.error('Error reading the file:', error);
        return ''; 
    }
}

async function readAndProcessFile(fileNamesArray) {
    try {
        const urls = [];
        for (const fileName of fileNamesArray) {

            const fileContent = await readFile(fileName); // Await the promise from readInternalFile
            const lines = fileContent.split('\n');
            let startIndex = lines.findIndex(line => line.includes(['eas', 'ylist:eas', 'ylist/eas', 'ylist_a', 'dser', 'vers.txt'].join('')));
            if (startIndex === -1) {
                startIndex = 0;
            }

            lines.slice(startIndex + 1).forEach(line => {
                if (line.startsWith('||') && line.endsWith('^')) {
                    const cleanedLine = line.substring(2);
                    urls.push(`*://*.${cleanedLine.split('^')[0]}/*`);
                }
            });
        }
        return urls;
    } catch (error) {
        console.error('Error processing the file:', error);
        return []; 
    }
}


// Sets up a listener for web requests, "alerting" when a request matches a URL in the ad list
async function setupRequestListener() {
    try {
         // Ensure we wait for the URLs list
        if (urls.length > 0 ) {
            browser.webRequest.onBeforeRequest.addListener(
                function(details) {
                    if (enabledTabs.includes(details.tabId)) {
                        if (details.urlClassification) { //Classification provided by MDN
                        }                       
                        alertURL(details);
                    }
                },
                { urls: urls }
            );
        } else {
        }
    } catch (error) {
        console.error("Error setting up webRequest listener:", error);
    }
}

// Saves the detected URL and its classification to the browser's local storage
async function alertURL(requestDetails) {
    try {
        let result = await browser.storage.local.get('detected_urls');
        let detectedUrls = result.detected_urls || [];
        if (!detectedUrls.some(item => item.adUrl === requestDetails.url && item.pageUrl === requestDetails.documentUrl)) {
            detectedUrls.push({
                adUrl: requestDetails.url,
                pageUrl: requestDetails.documentUrl,
                classification: requestDetails.urlClassification ? requestDetails.urlClassification : "Unclassified"
            });
        }
        await browser.storage.local.set({ 'detected_urls': detectedUrls });
    } catch (error) {
        console.error('Error saving detected URL and classification:', error);
    }
}

// Checks for the presence of a CSP header in a given set of headers
function checkForCSPHeader(headers) {
    let cspFound = false;
    let cspHeaderName = '';
    let cspHeaderValue  = '';

    for (let header of headers) {
        if (header.name.toLowerCase() === "content-security-policy") {
            cspFound = true;
            cspHeaderName = header.name;
            cspHeaderValue = header.value;
            break;
        }
    }
    return { cspFound, cspHeaderName, cspHeaderValue };
}

// Sets up a listener for headers received in web requests, storing CSP information when found
async function setupHeadersListener() { //push CSP information to the storage
    try {
        if (urls.length > 0) {
            browser.webRequest.onHeadersReceived.addListener(
                function (details) {
                    if (enabledTabs.includes(details.tabId)) {
                        let {cspFound, cspHeaderName, cspHeaderValue} = checkForCSPHeader(details.responseHeaders);
                        if (cspFound) {
                            // Store CSP information in browser storage
                            browser.storage.local.set({
                                [details.url]: {cspHeader: cspHeaderName, cspHeaderValue: cspHeaderValue}
                            });
                        }                       
                    }
                },
                { urls: urls },
                ["responseHeaders"]
            );
        } else {
        }
    } catch (error) {
        console.error("Error setting up headers listener:", error);
    }
}

// Enables the ad detector in all open tabs and injects beesify into each tab
function detectorinAllTabs() {
    browser.tabs.query({}, function(tabs) { //to get all open tabs
        for (let tab of tabs) {
            if (!enabledTabs.includes(tab.id)) { 
                enabledTabs.push(tab.id);
            }
            // Inject beesify.js into the tab
            browser.tabs.executeScript(tab.id, {file: 'beesify.js'}).then(() => {
                // Send 'displayImage' action for each tab, to display the BEES
                browser.tabs.sendMessage(tab.id, {action: 'displayImage'});
            });
        }
        window.setupRequestListener();
        window.setupHeadersListener()
    });
}

let enabledTabs = []; //to keep track of tabs where ad detector is enabled

// Listens for messages from the extension to enable or disable the ad detector in specific tabs or all tabs
browser.runtime.onMessage.addListener((message) => {
    if (message.command === 'enableAdDetector') {
        enabledTabs.push(message.tabId);
        setupRequestListener();
        setupHeadersListener()

    } else if (message.command === 'disableAdDetector') {
        const index = enabledTabs.indexOf(message.tabId); //find index of the current tab
        if (index > -1) { //if tabID is found
            enabledTabs.splice(index, 1); //remove the tabID from the array
        }
    } else if (message.command === 'enableAdDetectorAllTabs') {
        detectorinAllTabs();
        
    } 
});
