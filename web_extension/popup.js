//Browser action popup script. Manages the button listeners and actions triggered from the popup menu
document.getElementById('displayButton').addEventListener('click', function() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.tabs.sendMessage(tabs[0].id, {action: "displayImage"});//send a message to the active tab to display the image
        browser.runtime.sendMessage({command: 'enableAdDetector', tabId: tabs[0].id}); //functionality to enable ad detector
    });
});

document.getElementById('removeButton').addEventListener('click', function() { 
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.tabs.sendMessage(tabs[0].id, {action: "removeImage"});
        browser.runtime.sendMessage({command: 'disableAdDetector', tabId: tabs[0].id}); //functionality to disable ad detector
  
    });
});


document.getElementById('enableAllButton').addEventListener('click', function() {
    //send a message to the background script to enable the ad detector in all tabs
    browser.runtime.sendMessage({command: 'enableAdDetectorAllTabs'});//enable ad detector for all tabs
});

