//Content script: finds matches in CSS selectors and stores the src URLs of the iframes in the detected_urls storage
(async function() {
    const fileUrl = ['https://', 'eas', 'ylist.to/', 'eas', 'ylist/', 'eas', 'ylist.txt'].join('');


    try {
        const text = await (await fetch(fileUrl)).text();
        const lines = text.split('\n');
        const startIndex = lines.findIndex(line => line.includes(['!', ' *** ', 'eas', 'ylist:', 'eas', 'ylist/', 'eas', 'ylist_general_hide.txt', ' ***'].join('')));
        const cssSelectors = lines.slice(startIndex + 1).filter(line => line.startsWith('##')).map(id => id.substring(2).trim()).filter(Boolean);

        const matchingElements = document.querySelectorAll(cssSelectors.join(", "));
        let iframeSrcs = [];

        matchingElements.forEach(element => {
            const iframes = element.querySelectorAll('iframe');

            iframes.forEach(iframe => {
                iframeSrcs.push(iframe.src);
            });
        });

        let result = await browser.storage.local.get('detected_urls');

        for (const src of iframeSrcs) {

                let detectedUrls = result.detected_urls || [];
                if (!detectedUrls.some(item => item.adUrl === src && item.pageUrl === window.location.href)) {
                    detectedUrls.push({adUrl: src, pageUrl: window.location.href});
                }
        }
        await browser.storage.local.set({ 'detected_urls': detectedUrls });
    } catch (error) {
        console.error('Failed to fetch element IDs from file:', error);
    }

})();