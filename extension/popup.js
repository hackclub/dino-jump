document.addEventListener('DOMContentLoaded', async function() {
    const workspaceStatus = document.getElementById('workspace-status');
    const sendBtn = document.getElementById('send-btn');
    const statusDiv = document.getElementById('status');

    let currentTokens = null;

    function showStatus(message, isError = false) {
        statusDiv.textContent = message;
        statusDiv.className = isError ? 'workspace-check invalid' : 'workspace-check valid';
        statusDiv.style.display = 'block';
    }

    async function checkCurrentWorkspace() {
        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            const currentTab = tabs[0];

            if (!currentTab || !currentTab.url) {
                workspaceStatus.textContent = 'Unable to check current tab';
                workspaceStatus.className = 'workspace-check invalid';
                sendBtn.disabled = true;
                return;
            }

            const url = currentTab.url;
            const isHackClubWorkspace = url.includes('hackclub.slack.com') || 
                                      url.includes('app.slack.com/client/T0266FRGM');

            if (isHackClubWorkspace) {
                workspaceStatus.textContent = '✓ You are on the Hack Club Slack workspace';
                workspaceStatus.className = 'workspace-check valid';
                
                // Try to get tokens from content script
                try {
                    const response = await chrome.tabs.sendMessage(currentTab.id, { action: 'getTokens' });
                    currentTokens = response.tokens;
                    
                    // If we got the xoxc token but not the xoxd cookie, try to get it via cookies API
                    if (currentTokens && currentTokens.isHackClub && currentTokens.xoxc && !currentTokens.xoxd) {
                        console.log('Got xoxc token but no xoxd cookie, trying cookies API...');
                        try {
                            const allCookies = await chrome.cookies.getAll({ domain: '.slack.com' });
                            console.log('Available cookies via API:', allCookies.map(c => `${c.name}: ${c.value.substring(0, 20)}...`));
                            
                            // Look for 'd' cookie with xoxd value
                            const dCookie = allCookies.find(cookie => 
                                cookie.name === 'd' && cookie.value.startsWith('xoxd-')
                            );
                            
                            if (dCookie) {
                                currentTokens.xoxd = dCookie.value;
                                console.log('Found xoxd session cookie via popup API:', dCookie.value.substring(0, 12) + '...');
                            } else {
                                console.log('No "d" cookie with xoxd value found via popup API');
                                // Look for any cookie value starting with xoxd-
                                const xoxdCookie = allCookies.find(cookie => cookie.value.startsWith('xoxd-'));
                                if (xoxdCookie) {
                                    currentTokens.xoxd = xoxdCookie.value;
                                    console.log(`Found xoxd value in cookie "${xoxdCookie.name}" via popup API:`, xoxdCookie.value.substring(0, 12) + '...');
                                }
                            }
                        } catch (cookieError) {
                            console.error('Failed to get cookies via popup API:', cookieError);
                        }
                    }
                    
                    if (currentTokens && currentTokens.isHackClub && currentTokens.xoxc && currentTokens.xoxd) {
                        sendBtn.disabled = false;
                    } else {
                        sendBtn.disabled = true;
                        const missing = [];
                        if (!currentTokens.xoxc) missing.push('xoxc token');
                        if (!currentTokens.xoxd) missing.push('xoxd cookie');
                        showStatus(`Missing: ${missing.join(' and ')}. Make sure you are logged in.`, true);
                    }
                } catch (error) {
                    sendBtn.disabled = true;
                    showStatus('Content script not ready. Refresh the page and try again.', true);
                }
            } else if (url.includes('slack.com')) {
                workspaceStatus.textContent = '⚠️ You are on a different Slack workspace';
                workspaceStatus.className = 'workspace-check invalid';
                sendBtn.disabled = true;
            } else {
                workspaceStatus.textContent = 'Navigate to the Hack Club Slack workspace';
                workspaceStatus.className = 'workspace-check invalid';
                sendBtn.disabled = true;
            }
        } catch (error) {
            workspaceStatus.textContent = 'Error checking workspace';
            workspaceStatus.className = 'workspace-check invalid';
            sendBtn.disabled = true;
        }
    }

    async function sendTokens() {
        if (!currentTokens || !currentTokens.isHackClub || !currentTokens.xoxc || !currentTokens.xoxd) {
            showStatus('Tokens not available. Please refresh and try again.', true);
            return;
        }

        sendBtn.disabled = true;
        sendBtn.textContent = 'Sending...';
        
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'sendTokens',
                tokens: currentTokens
            });

            if (response.success) {
                showStatus(response.message, false);
            } else {
                showStatus(response.message || 'Failed to send tokens', true);
            }
        } catch (error) {
            showStatus('Error: ' + error.message, true);
        } finally {
            sendBtn.textContent = 'Extract and Send Tokens';
            await checkCurrentWorkspace(); // Re-enable button if appropriate
        }
    }

    sendBtn.addEventListener('click', sendTokens);

    // Check workspace on popup open
    await checkCurrentWorkspace();
});
