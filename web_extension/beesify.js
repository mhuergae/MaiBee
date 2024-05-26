//Add bees image to the layout when the BEES option is activated
var images = []; 
var intervals = []; 

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "displayImage") {
        for (var i = 0; i < 40; i++) {
            var img = document.createElement('img');
            img.src = chrome.runtime.getURL('honeybee.png');
            img.style.position = 'fixed';
            img.style.top = Math.random() * 100 + '%';
            img.style.left = Math.random() * 100 + '%';
            img.style.transform = 'translate(-50%, -50%)';
            img.style.zIndex = '1000';
            document.body.appendChild(img);
            images.push(img); // store the image

            // move the image randomly every 2000 milliseconds
            (function(img) {
                var intervalId = setInterval(function() {
                    img.style.top = Math.random() * 100 + '%';
                    img.style.left = Math.random() * 100 + '%';
                }, 2000);
                intervals.push(intervalId); // store the interval ID
            })(img);
        }
        setTimeout(function() { //set the image to only appear 5sec
            for (var i = 0; i < images.length; i++) {
                document.body.removeChild(images[i]); // remove the image
            }
            for (var i = 0; i < intervals.length; i++) {
                clearInterval(intervals[i]); // clear the interval
            }
            images = []; // clear the images
            intervals = []; // clear the interval IDs
        }, 5000); 

    } else if (request.action === "removeImage") { //when REMOVE BEES button pressed
        for (var i = 0; i < images.length; i++) {
            document.body.removeChild(images[i]); // 
        }
        for (var i = 0; i < intervals.length; i++) {
            clearInterval(intervals[i]); 
        }
        images = []; 
        intervals = []; 
    }
});