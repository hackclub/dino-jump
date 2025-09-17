// Background script for the extension

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'sendTokens') {
        // Handle async operation properly
        handleSendTokens(message.tokens, sendResponse);
        return true; // Keep the message channel open for async response
    }
});

async function handleSendTokens(tokens, sendResponse) {
    try {
        const response = await fetch('http://localhost:8080/tokens', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                xoxc_token: tokens.xoxc,
                xoxd_cookie: tokens.xoxd
            })
        });

        const result = await response.json();
        sendResponse({ 
            success: response.ok, 
            message: result.message || result.error,
            status: response.status
        });
    } catch (error) {
        sendResponse({ 
            success: false, 
            message: 'Failed to connect to server: ' + error.message,
            status: 0
        });
    }
}
