const VT_API_KEY = 'YOUR API KEY';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "proveriURL") {
        const encodedUrl = btoa(request.url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

        // Checking Function
        const checkVT = async () => {
            try {
                let response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
                    headers: { 'x-apikey': VT_API_KEY }
                });

                if (response.status === 404) {
                    // If it doesn't exist, let the user know
                    await fetch(`https://www.virustotal.com/api/v3/urls`, {
                        method: 'POST',
                        headers: { 'x-apikey': VT_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({ 'url': request.url })
                    });
                    sendResponse({ status: "scanning", maliciousCount: 0 });
                } else {
                    const data = await response.json();
                    sendResponse({ status: "done", maliciousCount: data.data.attributes.last_analysis_stats.malicious });
                }
            } catch (e) {
                sendResponse({ status: "error", maliciousCount: 0 });
            }
        };

        checkVT();
        return true; // Keep the channel open
    }
});