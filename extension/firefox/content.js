// Content script to extract Slack tokens (Firefox)
(function() {
  'use strict';

  const HACK_CLUB_TEAM_ID = 'T0266FRGM';
  const HACK_CLUB_DOMAIN = 'hackclub.slack.com';

  function isHackClubWorkspace() {
    // Check if we're on the Hack Club domain
    if (
      window.location.hostname === HACK_CLUB_DOMAIN ||
      window.location.href.includes('app.slack.com/client/' + HACK_CLUB_TEAM_ID)
    ) {
      return true;
    }

    // Check team ID from boot data
    try {
      const bootData = localStorage.getItem('localConfig_v2');
      if (bootData) {
        const config = JSON.parse(bootData);
        if (config.teams) {
          for (const team of Object.values(config.teams)) {
            if (team.id === HACK_CLUB_TEAM_ID) {
              return true;
            }
          }
        }
      }

      // Check window.TS.boot_data for team ID
      if (window.TS && window.TS.boot_data && window.TS.boot_data.team_id === HACK_CLUB_TEAM_ID) {
        return true;
      }
    } catch (error) {
      console.error('Error checking workspace:', error);
    }

    return false;
  }

  async function extractTokens() {
    const tokens = {
      xoxc: null,
      xoxd: null,
      isHackClub: false
    };

    // First check if this is the Hack Club workspace
    if (!isHackClubWorkspace()) {
      console.log('Not Hack Club workspace, skipping token extraction');
      return tokens;
    }

    tokens.isHackClub = true;

    try {
      // Method 1: Extract xoxc token from localStorage (recommended by slackdump docs)
      const bootData = localStorage.getItem('localConfig_v2');
      console.log('localStorage bootData:', bootData ? 'found' : 'not found');

      if (bootData) {
        const config = JSON.parse(bootData);
        console.log('Config teams:', config.teams ? Object.keys(config.teams) : 'no teams');

        if (config.teams && config.teams[HACK_CLUB_TEAM_ID]) {
          const team = config.teams[HACK_CLUB_TEAM_ID];
          console.log('Hack Club team found:', team);

          if (team.token && team.token.startsWith('xoxc-')) {
            tokens.xoxc = team.token;
            console.log('Found xoxc token:', team.token.substring(0, 12) + '...');
          } else {
            console.log('No xoxc token in team data, token field:', team.token);
          }
        } else {
          console.log('Hack Club team not found in config');
        }
      }

      // Method 2: Try to extract xoxd cookie from document.cookie (limited access)
      console.log('Checking document.cookie for xoxd cookie...');
      const cookies = document.cookie.split(';');
      console.log('Available cookies via document.cookie:', cookies.map(c => c.trim().split('=')[0]));

      for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'd' && value && value.startsWith('xoxd-')) {
          tokens.xoxd = value;
          console.log('Found xoxd session cookie:', value.substring(0, 12) + '...');
          break;
        }
      }

      if (!tokens.xoxd) {
        console.log('No xoxd cookie found in document.cookie - this may be httpOnly');
      }

      // Method 3: Fallback - check for xoxc tokens in script tags if not found in localStorage
      if (!tokens.xoxc) {
        const scripts = document.getElementsByTagName('script');
        for (const script of scripts) {
          const content = script.innerHTML;

          // Look for xoxc tokens
          const xoxcMatch = content.match(/["']?(xoxc-[a-zA-Z0-9-]+)["']?/);
          if (xoxcMatch) {
            tokens.xoxc = xoxcMatch[1];
            break;
          }
        }
      }

      // Method 4: Check window object for xoxc token (only for Hack Club)
      if (!tokens.xoxc && window.TS && window.TS.boot_data && window.TS.boot_data.team_id === HACK_CLUB_TEAM_ID) {
        if (window.TS.boot_data.api_token && window.TS.boot_data.api_token.startsWith('xoxc-')) {
          tokens.xoxc = window.TS.boot_data.api_token;
        }
      }

    } catch (error) {
      console.error('Error extracting tokens:', error);
    }

    console.log('Final tokens:', {
      isHackClub: tokens.isHackClub,
      hasXoxc: !!tokens.xoxc,
      hasXoxd: !!tokens.xoxd
    });

    return tokens;
  }

  // Listen for messages from popup (Firefox promises style)
  browser.runtime.onMessage.addListener(async (request, sender) => {
    if (request.action === 'getTokens') {
      try {
        const tokens = await extractTokens();
        return { tokens };
      } catch (error) {
        console.error('Error extracting tokens:', error);
        return { tokens: { isHackClub: false, xoxc: null, xoxd: null } };
      }
    }
  });
})();
