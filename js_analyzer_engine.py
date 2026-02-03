# -*- coding: utf-8 -*-
"""
JS Analyzer Engine - Standalone analysis engine without Burp dependencies
"""

import re
import sys


# ==================== ENDPOINT PATTERNS ====================
# Focus on high-value API endpoints only

ENDPOINT_PATTERNS = [
    # API endpoints
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    
    # OAuth/Auth endpoints
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    
    # Sensitive paths
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    
    # Well-known paths
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
]

# URL patterns - full URLs
URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    # Cloud storage
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
]

# Secret patterns
SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API"),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live"),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub PAT"),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token"),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT"),
    (re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'), "Private Key"),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB"),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL"),
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), "Algolia Admin API Key"),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), "Algolia Application ID"),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), "Cloudflare API Token"),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), "Cloudflare Service Key"),
    (re.compile(r'(mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)'), "MySQL URI with Credentials"),
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), "Segment Public API Token"),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})'), "Segment API Key"),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'), "Facebook App ID"),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b'), "Facebook Secret Key"),
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), "Facebook Access Token"),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'), "Google OAuth2 Access Token"),
    # Additional TruffleHog patterns
    (re.compile(r'(sk_test_[0-9a-zA-Z]{24,})'), "Stripe Test Key"),
    (re.compile(r'(rk_live_[0-9a-zA-Z]{24,})'), "Stripe Restricted Key"),
    (re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'), "Stripe Publishable Key"),
    (re.compile(r'(pk_test_[0-9a-zA-Z]{24,})'), "Stripe Test Publishable Key"),
    (re.compile(r'(xoxa-[0-9a-zA-Z-]{10,48})'), "Slack App Token"),
    (re.compile(r'(xoxp-[0-9a-zA-Z-]{10,48})'), "Slack User Token"),
    (re.compile(r'(xoxo-[0-9a-zA-Z-]{10,48})'), "Slack Bot Token"),
    (re.compile(r'(xoxs-[0-9a-zA-Z-]{10,48})'), "Slack Workspace Token"),
    (re.compile(r'(sk-[0-9a-zA-Z]{32,})'), "Generic Secret Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API Key"),
    (re.compile(r'(AIzaSy[0-9a-zA-Z_-]{35})'), "Google OAuth Token"),
    (re.compile(r'(ya29\.[a-zA-Z0-9_-]{100,})'), "Google OAuth2 Access Token Long"),
    (re.compile(r'(1/[0-9A-Za-z_-]{43})'), "Google OAuth2 Refresh Token"),
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Access Key ID"),
    (re.compile(r'(aws_access_key_id\s*=\s*[A-Z0-9]{20})'), "AWS Access Key ID Config"),
    (re.compile(r'(aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40})'), "AWS Secret Access Key"),
    (re.compile(r'(-----BEGIN DSA PRIVATE KEY-----)'), "DSA Private Key"),
    (re.compile(r'(-----BEGIN OPENSSH PRIVATE KEY-----)'), "OpenSSH Private Key"),
    (re.compile(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)'), "PGP Private Key"),
    (re.compile(r'(-----BEGIN ENCRYPTED PRIVATE KEY-----)'), "Encrypted Private Key"),
    (re.compile(r'(gho_[0-9a-zA-Z]{36})'), "GitHub OAuth Token"),
    (re.compile(r'(ghu_[0-9a-zA-Z]{36})'), "GitHub User Token"),
    (re.compile(r'(ghs_[0-9a-zA-Z]{36})'), "GitHub Server Token"),
    (re.compile(r'(ghr_[0-9a-zA-Z]{76})'), "GitHub Refresh Token"),
    (re.compile(r'(github_pat_[0-9a-zA-Z_]{82})'), "GitHub Personal Access Token"),
    (re.compile(r'(xoxb-[0-9a-zA-Z-]{10,48})'), "Slack Bot Token"),
    (re.compile(r'(xoxa-2-[0-9a-zA-Z-]{10,48})'), "Slack App-Level Token"),
    (re.compile(r'(TQDM[A-Z0-9]{32})'), "Telegram Bot Token"),
    (re.compile(r'([0-9]+-[0-9A-Za-z_]{32})'), "Telegram API ID"),
    (re.compile(r'(sk-[0-9a-zA-Z]{48})'), "OpenAI API Key"),
    (re.compile(r'(org-[0-9a-zA-Z]{24,})'), "OpenAI Organization ID"),
    (re.compile(r'(pk_[0-9a-zA-Z]{32,})'), "Pusher Public Key"),
    (re.compile(r'(sk_[0-9a-zA-Z]{32,})'), "Pusher Secret Key"),
    (re.compile(r'(access_token["\']?\s*[:=]\s*["\']?([0-9a-zA-Z\-_]{20,})["\']?)'), "Generic Access Token"),
    (re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?([0-9a-zA-Z\-_]{20,})["\']?)'), "Generic API Key"),
    (re.compile(r'(secret[_-]?key["\']?\s*[:=]\s*["\']?([0-9a-zA-Z\-_]{20,})["\']?)'), "Generic Secret Key"),
    (re.compile(r'(apikey["\']?\s*[:=]\s*["\']?([0-9a-zA-Z\-_]{20,})["\']?)'), "API Key Variant"),
    (re.compile(r'(api[_-]?secret["\']?\s*[:=]\s*["\']?([0-9a-zA-Z\-_]{20,})["\']?)'), "API Secret"),
    (re.compile(r'(bearer["\']?\s*[:=]\s*["\']?([0-9a-zA-Z\-_]{20,})["\']?)'), "Bearer Token"),
    (re.compile(r'(authorization["\']?\s*[:=]\s*["\']?bearer\s+([0-9a-zA-Z\-_]{20,})["\']?)'), "Authorization Bearer"),
    (re.compile(r'(redis://[^\s"\'<>]+)'), "Redis URI"),
    (re.compile(r'(amqp://[^\s"\'<>]+)'), "RabbitMQ URI"),
    (re.compile(r'(sqs://[^\s"\'<>]+)'), "AWS SQS URI"),
    (re.compile(r'(s3://[^\s"\'<>]+)'), "AWS S3 URI"),
    (re.compile(r'(gcp://[^\s"\'<>]+)'), "GCP URI"),
    (re.compile(r'(azure://[^\s"\'<>]+)'), "Azure URI"),
    (re.compile(r'(firebase[_-]?[a-z]*[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Firebase Token"),
    (re.compile(r'(twilio[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{32})["\']?)'), "Twilio API Key"),
    (re.compile(r'(mailgun[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{32})["\']?)'), "Mailgun API Key"),
    (re.compile(r'(sendgrid[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{69})["\']?)'), "SendGrid API Key"),
    (re.compile(r'(nexmo[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([0-9a-f]{32})["\']?)'), "Nexmo API Key"),
    (re.compile(r'(paypal[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{20,})["\']?)'), "PayPal Token"),
    (re.compile(r'(square[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{20,})["\']?)'), "Square API Key"),
    (re.compile(r'(shopify[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{32})["\']?)'), "Shopify API Key"),
    (re.compile(r'(heroku[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?)'), "Heroku API Key"),
    (re.compile(r'(datadog[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{32})["\']?)'), "Datadog API Key"),
    (re.compile(r'(newrelic[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{40})["\']?)'), "New Relic API Key"),
    (re.compile(r'(sentry[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{64})["\']?)'), "Sentry DSN"),
    (re.compile(r'(rollbar[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{32})["\']?)'), "Rollbar Access Token"),
    (re.compile(r'(jira[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{24,})["\']?)'), "Jira API Token"),
    (re.compile(r'(confluence[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{24,})["\']?)'), "Confluence API Token"),
    (re.compile(r'(bitbucket[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Bitbucket API Key"),
    (re.compile(r'(gitlab[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "GitLab Token"),
    (re.compile(r'(asana[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([0-9]{16})["\']?)'), "Asana API Key"),
    (re.compile(r'(trello[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?)'), "Trello API Key"),
    (re.compile(r'(discord[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{59,})["\']?)'), "Discord Bot Token"),
    (re.compile(r'(zoom[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Zoom API Key"),
    (re.compile(r'(twitch[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{30})["\']?)'), "Twitch API Key"),
    (re.compile(r'(youtube[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{39})["\']?)'), "YouTube API Key"),
    (re.compile(r'(instagram[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([0-9a-f]{32})["\']?)'), "Instagram Access Token"),
    (re.compile(r'(twitter[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{25,})["\']?)'), "Twitter API Key"),
    (re.compile(r'(linkedin[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16})["\']?)'), "LinkedIn API Key"),
    (re.compile(r'(pinterest[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?)'), "Pinterest Access Token"),
    (re.compile(r'(reddit[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Reddit API Key"),
    (re.compile(r'(tiktok[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "TikTok Access Token"),
    (re.compile(r'(snapchat[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Snapchat API Key"),
    (re.compile(r'(dropbox[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{15})["\']?)'), "Dropbox Access Token"),
    (re.compile(r'(onedrive[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "OneDrive Access Token"),
    (re.compile(r'(box[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?)'), "Box API Key"),
    (re.compile(r'(google[_-]?[a-z]*[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Google Service Account"),
    (re.compile(r'(microsoft[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Microsoft API Key"),
    (re.compile(r'(azure[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{32,})["\']?)'), "Azure Key"),
    (re.compile(r'(aws[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?)'), "AWS Key Variant"),
    (re.compile(r'(amazon[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?)'), "Amazon Key"),
    (re.compile(r'(digitalocean[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-f0-9]{64})["\']?)'), "DigitalOcean Token"),
    (re.compile(r'(linode[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{64})["\']?)'), "Linode API Key"),
    (re.compile(r'(vultr[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{36})["\']?)'), "Vultr API Key"),
    (re.compile(r'(cloudflare[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{40})["\']?)'), "Cloudflare Global API Key"),
    (re.compile(r'(fastly[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?)'), "Fastly API Key"),
    (re.compile(r'(keycdn[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?)'), "KeyCDN API Key"),
    (re.compile(r'(maxcdn[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32})["\']?)'), "MaxCDN API Key"),
    (re.compile(r'(bunny[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-f0-9]{32})["\']?)'), "BunnyCDN API Key"),
    (re.compile(r'(cloudinary[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([0-9]{13}:[a-zA-Z0-9_-]{27})["\']?)'), "Cloudinary API Key"),
    (re.compile(r'(imgur[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-f0-9]{40})["\']?)'), "Imgur API Key"),
    (re.compile(r'(unsplash[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{43})["\']?)'), "Unsplash Access Key"),
    (re.compile(r'(pexels[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{56})["\']?)'), "Pexels API Key"),
    (re.compile(r'(shutterstock[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Shutterstock API Key"),
    (re.compile(r'(adobe[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-f0-9]{32})["\']?)'), "Adobe API Key"),
    (re.compile(r'(figma[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{22})["\']?)'), "Figma Access Token"),
    (re.compile(r'(sketch[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Sketch API Key"),
    (re.compile(r'(invision[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "InVision API Key"),
    (re.compile(r'(zeplin[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Zeplin API Key"),
    (re.compile(r'(marvel[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Marvel API Key"),
    (re.compile(r'(dribbble[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{40})["\']?)'), "Dribbble Access Token"),
    (re.compile(r'(behance[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Behance API Key"),
    (re.compile(r'(deviantart[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "DeviantArt API Key"),
    (re.compile(r'(artstation[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "ArtStation API Key"),
    (re.compile(r'(codepen[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "CodePen API Key"),
    (re.compile(r'(jsfiddle[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "JSFiddle API Key"),
    (re.compile(r'(repl[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Repl.it API Key"),
    (re.compile(r'(glitch[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?)'), "Glitch API Key"),
    (re.compile(r'(vercel[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{24})["\']?)'), "Vercel API Token"),
    (re.compile(r'(netlify[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{43})["\']?)'), "Netlify API Token"),
    (re.compile(r'(surge[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Surge.sh Token"),
    (re.compile(r'(zeit[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Zeit API Token"),
    (re.compile(r'(railway[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Railway API Token"),
    (re.compile(r'(render[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Render API Token"),
    (re.compile(r'(fly[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Fly.io API Token"),
    (re.compile(r'(scaleway[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Scaleway API Key"),
    (re.compile(r'(ovh[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "OVH API Key"),
    (re.compile(r'(gandi[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Gandi API Key"),
    (re.compile(r'(namecheap[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Namecheap API Key"),
    (re.compile(r'(godaddy[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "GoDaddy API Key"),
    (re.compile(r'(cloudflare[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-z0-9]{40})["\']?)'), "Cloudflare Global API Key"),
    (re.compile(r'(route53[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?)'), "AWS Route53 Key"),
    (re.compile(r'(dnsimple[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "DNSimple API Token"),
    (re.compile(r'(dynu[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Dynu API Key"),
    (re.compile(r'(noip[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "No-IP API Key"),
    (re.compile(r'(duckdns[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "DuckDNS Token"),
    (re.compile(r'(freedns[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "FreeDNS API Key"),
    (re.compile(r'(zoneedit[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "ZoneEdit API Key"),
    (re.compile(r'(enom[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "eNom API Key"),
    (re.compile(r'(register[_-]?[a-z]*[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Register.com API Key"),
    (re.compile(r'(1and1[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "1&1 API Key"),
    (re.compile(r'(ionos[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "IONOS API Key"),
    (re.compile(r'(hostgator[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "HostGator API Key"),
    (re.compile(r'(bluehost[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Bluehost API Key"),
    (re.compile(r'(siteground[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "SiteGround API Key"),
    (re.compile(r'(dreamhost[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "DreamHost API Key"),
    (re.compile(r'(a2[_-]?[a-z]*[_-]?hosting["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "A2 Hosting API Key"),
    (re.compile(r'(inmotion[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "InMotion Hosting API Key"),
    (re.compile(r'(liquidweb[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Liquid Web API Key"),
    (re.compile(r'(wpengine[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "WP Engine API Key"),
    (re.compile(r'(kinsta[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Kinsta API Key"),
    (re.compile(r'(pantheon[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Pantheon API Key"),
    (re.compile(r'(acquia[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Acquia API Key"),
    (re.compile(r'(platform[_-]?[a-z]*[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Platform.sh API Key"),
    (re.compile(r'(amazonaws[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?)'), "Amazon AWS Key"),
    (re.compile(r'(gcp[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Google Cloud Platform Key"),
    (re.compile(r'(azure[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{32,})["\']?)'), "Microsoft Azure Key"),
    (re.compile(r'(ibm[_-]?[a-z]*[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "IBM Cloud API Key"),
    (re.compile(r'(oracle[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Oracle Cloud API Key"),
    (re.compile(r'(alibaba[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Alibaba Cloud API Key"),
    (re.compile(r'(tencent[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Tencent Cloud API Key"),
    (re.compile(r'(baidu[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Baidu Cloud API Key"),
    (re.compile(r'(yandex[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Yandex Cloud API Key"),
    (re.compile(r'(naver[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Naver Cloud API Key"),
    (re.compile(r'(kakao[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Kakao API Key"),
    (re.compile(r'(wechat[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "WeChat API Key"),
    (re.compile(r'(qq[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "QQ API Key"),
    (re.compile(r'(weibo[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Weibo API Key"),
    (re.compile(r'(douyin[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Douyin API Key"),
    (re.compile(r'(kuaishou[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Kuaishou API Key"),
    (re.compile(r'(bilibili[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Bilibili API Key"),
    (re.compile(r'(acfun[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "AcFun API Key"),
    (re.compile(r'(youku[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Youku API Key"),
    (re.compile(r'(iqiyi[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "iQIYI API Key"),
    (re.compile(r'(tencent[_-]?[a-z]*[_-]?video["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Tencent Video API Key"),
    (re.compile(r'(pptv[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "PPTV API Key"),
    (re.compile(r'(sohu[_-]?[a-z]*[_-]?tv["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Sohu TV API Key"),
    (re.compile(r'(letv[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "LeTV API Key"),
    (re.compile(r'(fengxing[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Fengxing API Key"),
    (re.compile(r'(ppstream[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "PPStream API Key"),
    (re.compile(r'(pandatv[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Panda TV API Key"),
    (re.compile(r'(douyu[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Douyu API Key"),
    (re.compile(r'(huya[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Huya API Key"),
    (re.compile(r'(zhanqi[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Zhanqi API Key"),
    (re.compile(r'(longzhu[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Longzhu API Key"),
    (re.compile(r'(quanmin[_-]?[a-z]*[_-]?tv["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Quanmin TV API Key"),
    (re.compile(r'(huoshan[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Huoshan API Key"),
    (re.compile(r'(inke[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Inke API Key"),
    (re.compile(r'(meipai[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Meipai API Key"),
    (re.compile(r'(miaopai[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Miaopai API Key"),
    (re.compile(r'(yizhibo[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Yizhibo API Key"),
    (re.compile(r'(inke[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Inke API Key"),
    (re.compile(r'(huajiao[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Huajiao API Key"),
    (re.compile(r'(6rooms[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "6Rooms API Key"),
    (re.compile(r'(showself[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "ShowSelf API Key"),
    (re.compile(r'(yizhibo[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Yizhibo API Key"),
    (re.compile(r'(inke[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Inke API Key"),
    (re.compile(r'(huajiao[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "Huajiao API Key"),
    (re.compile(r'(6rooms[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "6Rooms API Key"),
    (re.compile(r'(showself[_-]?[a-z]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?)'), "ShowSelf API Key"),
]

# Email pattern
EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# File patterns - detect references to sensitive file types
FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|xls|json|xml|yaml|yml|'  # Data files
    r'txt|log|conf|config|cfg|ini|env|'      # Config/logs
    r'bak|backup|old|orig|copy|'              # Backups
    r'key|pem|crt|cer|p12|pfx|'               # Certificates
    r'doc|docx|pdf|'                          # Documents
    r'zip|tar|gz|rar|7z|'                     # Archives
    r'sh|bat|ps1|py|rb|pl'                    # Scripts
    r'))["\']',
    re.IGNORECASE
)

# ==================== NOISE FILTERS ====================
# Extensive list of patterns to EXCLUDE

# Domains to exclude from URLs (XML namespaces, standards, etc.)
NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

# Path prefixes that indicate module imports (NOT real endpoints)
MODULE_PREFIXES = (
    './', '../', '.../', 
    './lib', '../lib', './utils', '../utils',
    './node_modules', '../node_modules',
    './src', '../src', './dist', '../dist',
)

# Patterns that are clearly internal JS/build artifacts
NOISE_PATTERNS = [
    # Module/library imports
    re.compile(r'^\.\.?/'),  # Starts with ./ or ../
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),  # Locale files: en.js, en-gb.js
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),  # Just locale: en, en-gb
    re.compile(r'-xform$'),  # Excel xform modules
    re.compile(r'^sha\d*$'),  # sha, sha1, sha256
    re.compile(r'^aes$|^des$|^md5$'),  # Crypto modules
    
    # PDF internal structure
    re.compile(r'^/[A-Z][a-z]+\s'),  # /Type /Font, /Filter /Standard
    re.compile(r'^/[A-Z][a-z]+$'),  # /Parent, /Kids, /Resources
    re.compile(r'^\d+ \d+ R$'),  # PDF object references
    
    # Excel/XML internal paths
    re.compile(r'^xl/'),  # Excel internal
    re.compile(r'^docProps/'),  # Document properties
    re.compile(r'^_rels/'),  # Relationships
    re.compile(r'^META-INF/'),  # Manifest
    re.compile(r'\.xml$'),  # XML files
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    
    # Build/bundler artifacts
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    
    # Generic noise
    re.compile(r'^\+'),  # Starts with +
    re.compile(r'^\$\{'),  # Template literal
    re.compile(r'^#'),  # Fragment only
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),  # Single letter paths
    re.compile(r'^/[A-Z]$'),  # Single letter paths
    re.compile(r'^http://$'),  # Empty http://
    re.compile(r'_ngcontent'),  # Angular internals
]

# Specific strings to exclude
NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}


class JSAnalyzerEngine:
    """Standalone JS Analyzer engine without Burp dependencies."""
    
    def __init__(self):
        self.seen_values = set()
    
    def analyze(self, content, source_url=None, mode=None):
        """
        Analyze JavaScript content and return findings.
        
        Args:
            content: JavaScript content as string
            source_url: Optional source URL for tracking
            mode: Optional mode(s) to filter categories. Can be:
                  - None: analyze all categories
                  - String: single mode ('secrets', 'endpoints', 'files', 'emails')
                  - List: multiple modes ['secrets', 'emails']
            
        Returns:
            Dictionary with categories: endpoints, urls, secrets, emails, files
        """
        if not content or len(content) < 50:
            return {
                "endpoints": [],
                "urls": [],
                "secrets": [],
                "emails": [],
                "files": [],
            }
        
        findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
        }
        
        source = source_url if source_url else "stdin"
        
        # Normalize mode to a list
        if mode is None:
            modes = None  # All modes
        elif isinstance(mode, str):
            modes = [m.strip() for m in mode.split(',')]
        elif isinstance(mode, list):
            modes = mode
        else:
            modes = None
        
        # Determine which categories to analyze based on mode(s)
        if modes is None:
            analyze_endpoints = True
            analyze_secrets = True
            analyze_emails = True
            analyze_files = True
        else:
            analyze_endpoints = "endpoints" in modes
            analyze_secrets = "secrets" in modes
            analyze_emails = "emails" in modes
            analyze_files = "files" in modes
        
        # 1. Extract endpoints
        if analyze_endpoints:
            for pattern in ENDPOINT_PATTERNS:
                for match in pattern.finditer(content):
                    value = match.group(1).strip()
                    if self._is_valid_endpoint(value):
                        if self._add_finding(findings["endpoints"], "endpoints", value, source):
                            pass
        
        # 2. URLs (always analyze if endpoints are analyzed)
        if analyze_endpoints:
            for pattern in URL_PATTERNS:
                for match in pattern.finditer(content):
                    value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                    if self._is_valid_url(value):
                        self._add_finding(findings["urls"], "urls", value, source)
        
        # 3. Secrets
        if analyze_secrets:
            for pattern, secret_type in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    # Key:value patterns have 2 groups: use only the inner value (group 2)
                    if match.lastindex and match.lastindex >= 2:
                        value = match.group(2).strip()
                    elif match.lastindex:
                        value = match.group(1).strip()
                    else:
                        value = match.group(0).strip()
                    if not value or len(value) < 10:
                        continue
                    # If value still looks like key:value or key="... (group1 leaked), strip or skip
                    value = self._strip_key_prefix(value)
                    if value is None:
                        continue
                    # Check context for variable declarations (false positive check)
                    if self._is_variable_declaration(content, match.start(), match.end()):
                        continue
                    if self._is_valid_secret(value, secret_type):
                        masked = value[:10] + "..." + value[-4:] if len(value) > 20 else value
                        self._add_finding(findings["secrets"], "secrets", masked, source, extra={"type": secret_type, "original_length": len(value)})
        
        # 4. Emails
        if analyze_emails:
            for match in EMAIL_PATTERN.finditer(content):
                value = match.group(1).strip()
                if self._is_valid_email(value):
                    self._add_finding(findings["emails"], "emails", value, source)
        
        # 5. Files (sensitive file references)
        if analyze_files:
            for match in FILE_PATTERNS.finditer(content):
                value = match.group(1).strip()
                if self._is_valid_file(value):
                    self._add_finding(findings["files"], "files", value, source)
        
        return findings
    
    def _get_source_name(self, url):
        """Extract source name from URL."""
        if not url:
            return "Unknown"
        try:
            source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
            if len(source_name) > 40:
                source_name = source_name[:40] + "..."
            return source_name
        except:
            return "Unknown"
    
    def _add_finding(self, findings_list, category, value, source, extra=None):
        """Add a finding if not duplicate."""
        key = category + ":" + value
        if key in self.seen_values:
            return False
        
        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source,
        }
        if extra:
            finding.update(extra)
        findings_list.append(finding)
        return True
    
    def _is_valid_endpoint(self, value):
        """Strict endpoint validation - reject noise."""
        if not value or len(value) < 3:
            return False
        
        # Check exact matches first
        if value in NOISE_STRINGS:
            return False
        
        # Check noise patterns
        for pattern in NOISE_PATTERNS:
            if pattern.search(value):
                return False
        
        # Must start with / and have some path
        if not value.startswith('/'):
            return False
        
        # Skip if just a single segment with no meaning
        parts = value.split('/')
        if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
            return False
        
        return True
    
    def _is_valid_url(self, value):
        """Strict URL validation."""
        if not value or len(value) < 15:
            return False
        
        val_lower = value.lower()
        
        # Check for noise domains
        for domain in NOISE_DOMAINS:
            if domain in val_lower:
                return False
        
        # Skip if contains placeholder patterns
        if '{' in value or 'undefined' in val_lower or 'null' in val_lower:
            return False
        
        # Skip data URIs
        if val_lower.startswith('data:'):
            return False
        
        # Skip if ends with common static extensions
        if any(val_lower.endswith(ext) for ext in ['.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf']):
            return False
        
        return True
    
    # Prefixes that indicate "key:value" or "key=\"..." leaked into value (reject or strip)
    _KEY_VALUE_PREFIX = re.compile(
        r'^(mango|line|box|google|api|bearer|secret|wechat|twilio|firebase|aws|azure)[_\w]*\s*[=:]\s*["\']?(.*)$',
        re.IGNORECASE
    )
    
    def _strip_key_prefix(self, value):
        """If value is key:value or key=\"..., return only the value part; else return value. Return None to skip."""
        if not value or len(value) < 10:
            return value
        m = self._KEY_VALUE_PREFIX.match(value.strip())
        if not m:
            return value
        rest = m.group(2).strip().strip('"').strip("'").strip()
        if len(rest) < 10:
            return None
        return rest
    
    def _is_valid_secret(self, value, secret_type=None):
        """Validate secrets."""
        if not value or len(value) < 10:
            return False
        
        val_lower = value.lower()
        if any(x in val_lower for x in ['example', 'placeholder', 'your', 'xxxx', 'test', 'link', 'name', 'sha256', 'sha1', 'md5']):
            return False
        
        # Reject truncated display values for any secret
        if "..." in value:
            return False
        
        # Key:value-style secrets (LINE, Mango, Box, etc.): reject UI/minified false positives
        # when the "value" looks like a JS key name or UI text, not a real API key
        key_like_prefixes = (
            'line', 'mango', 'box', 'tool', 'butt', 'button', 'inline', 'outline',
            'streamline', 'headline', 'deadline', 'guideline', 'linear', 'liner',
            'value', 'color', 'style', 'align', 'border', 'shadow', 'width', 'height',
        )
        if any(val_lower.startswith(p) for p in key_like_prefixes):
            return False
        # Reject if we got full match (key:value or key=value) — value must not start with key name + :=
        if re.match(r'^(mango|line|box|google|api|bearer|secret|wechat|firebase|aws|azure)[_\w]*\s*[=:]', val_lower):
            return False
        # Reject UI/CSS-like substrings (common in minified JS)
        ui_like = ('color', 'value', 'style', 'align', 'background', 'border', 'padding')
        if any(u in val_lower for u in ui_like):
            return False
        # Reject CamelCase word + suffix (e.g. Tool...g8g, Button...Cv_)
        if len(value) >= 4 and value[0].isupper() and value[1].islower():
            return False
        
        # Google OAuth2 Refresh Token: reject path-like values
        if secret_type == "Google OAuth2 Refresh Token":
            if value.count("/") > 1:
                return False
        
        # Telegram API ID: pattern [0-9]+-[0-9A-Za-z_]{32}; reject bit-size prefixes (256-, 128-, 512-)
        if secret_type == "Telegram API ID":
            if '-' in value:
                parts = value.split('-', 1)
                if len(parts) == 2 and parts[0].isdigit():
                    prefix = parts[0]
                    if prefix in ('256', '128', '512'):
                        return False
                    if len(parts[1]) == 32 and parts[1].lower().startswith('sha'):
                        return False
        
        return True
    
    def _is_variable_declaration(self, content, match_start, match_end):
        """Check if the match is part of a variable declaration (false positive)."""
        # Look at context before the match (up to 50 characters)
        context_start = max(0, match_start - 50)
        context = content[context_start:match_start]
        
        # Check for variable declaration patterns: name=, name =, name:, name :
        # Common patterns: var name=, let name=, const name=, name:, name =, etc.
        context_lower = context.lower()
        
        # Check for common variable declaration patterns before the match
        # Pattern: word characters followed by = or : or = or :
        var_patterns = [
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*$',  # name = (with spaces)
            r'[a-zA-Z_$][a-zA-Z0-9_$]*=\s*$',     # name= (no spaces)
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*:\s*$',  # name : (with spaces)
            r'[a-zA-Z_$][a-zA-Z0-9_$]*:\s*$',     # name: (no spaces)
        ]
        
        for pattern in var_patterns:
            if re.search(pattern, context):
                return True
        
        # Also check for common JS variable keywords followed by variable name
        js_keywords = ['var', 'let', 'const', 'function']
        for keyword in js_keywords:
            keyword_pattern = r'\b' + re.escape(keyword) + r'\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*[=:]\s*$'
            if re.search(keyword_pattern, context_lower):
                return True
        
        return False
    
    def _is_valid_email(self, value):
        """Validate emails."""
        if not value or '@' not in value:
            return False
        
        val_lower = value.lower()
        domain = value.split('@')[-1].lower()
        
        if domain in {'example.com', 'test.com', 'domain.com', 'placeholder.com'}:
            return False
        
        if any(x in val_lower for x in ['example', 'test', 'placeholder', 'noreply']):
            return False
        
        return True
    
    def _is_valid_file(self, value):
        """Validate file references."""
        if not value or len(value) < 3:
            return False
        
        val_lower = value.lower()
        
        # Skip common JS/build files
        if any(x in val_lower for x in [
            'package.json', 'tsconfig.json', 'webpack', 'babel',
            'eslint', 'prettier', 'node_modules', '.min.',
            'polyfill', 'vendor', 'chunk', 'bundle'
        ]):
            return False
        
        # Skip source maps
        if val_lower.endswith('.map'):
            return False
        
        # Skip common locale/language files
        if val_lower.endswith('.json') and len(value.split('/')[-1]) <= 7:
            return False
        
        return True
    
    def reset(self):
        """Reset seen values to allow re-analysis."""
        self.seen_values = set()
