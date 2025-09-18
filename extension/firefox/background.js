// Background script for Firefox (MV3 service worker)

browser.runtime.onMessage.addListener(async (message, sender) => {
  if (message && message.action === 'sendTokens') {
    try {
      const response = await fetch('http://localhost:8080/tokens', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          xoxc_token: message.tokens?.xoxc,
          xoxd_cookie: message.tokens?.xoxd
        })
      });

      let resultText = '';
      let resultJson = null;
      try {
        resultJson = await response.json();
      } catch (_) {
        resultText = await response.text();
      }

      return {
        success: response.ok,
        message: (resultJson && (resultJson.message || resultJson.error)) || resultText || '',
        status: response.status
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to connect to server: ' + (error?.message || String(error)),
        status: 0
      };
    }
  }
});
