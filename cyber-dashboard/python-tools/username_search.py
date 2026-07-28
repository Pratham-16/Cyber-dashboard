import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 6
MAX_WORKERS = 20
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9'
}


BLOCKED_STATUS_CODES = {403, 429, 503}


PLATFORMS = [
    ("GitHub",       "https://github.com/{}",                 "status",  None),
    ("GitLab",       "https://gitlab.com/{}",                 "status",  None),
    ("Reddit",       "https://www.reddit.com/user/{}",         "status",  None),
    ("Twitter/X",    "https://x.com/{}",                       "not_found_in_body", "This account doesn't exist"),
    ("Instagram",    "https://www.instagram.com/{}/",          "not_found_in_body", "Sorry, this page"),
    ("TikTok",       "https://www.tiktok.com/@{}",             "not_found_in_body", "Couldn't find this account"),
    ("Pinterest",    "https://www.pinterest.com/{}/",          "not_found_in_body", "Sorry! We couldn't find that page"),
    ("YouTube",      "https://www.youtube.com/@{}",            "not_found_in_body", "This page isn't available"),
    ("Twitch",       "https://www.twitch.tv/{}",               "not_found_in_body", "Sorry. Unless you've got a time machine"),
    ("Medium",       "https://medium.com/@{}",                 "status",  None),
    ("DeviantArt",   "https://www.deviantart.com/{}",          "not_found_in_body", "doesn't exist"),
    ("SoundCloud",   "https://soundcloud.com/{}",              "not_found_in_body", "Error 404"),
    ("Spotify",      "https://open.spotify.com/user/{}",       "status",  None),
    ("Steam",        "https://steamcommunity.com/id/{}",       "not_found_in_body", "The specified profile could not be found"),
    ("Telegram",     "https://t.me/{}",                        "not_found_in_body", "If you have Telegram"),
    ("VK",           "https://vk.com/{}",                      "not_found_in_body", "This page has been deleted"),
    ("Tumblr",       "https://{}.tumblr.com",                  "status",  None),
    ("Flickr",       "https://www.flickr.com/people/{}",       "not_found_in_body", "Page Not Found"),
    ("Behance",      "https://www.behance.net/{}",             "not_found_in_body", "Whoops"),
    ("Dribbble",     "https://dribbble.com/{}",                "not_found_in_body", "Whoops, that page is gone"),
    ("Keybase",      "https://keybase.io/{}",                  "not_found_in_body", "User not found"),
    ("Product Hunt", "https://www.producthunt.com/@{}",        "not_found_in_body", "Product Hunt is a curation"),
    ("HackerNews",   "https://news.ycombinator.com/user?id={}", "not_found_in_body", "No such user"),
    ("Codewars",     "https://www.codewars.com/users/{}",      "status",  None),
    ("HackerRank",   "https://www.hackerrank.com/{}",           "not_found_in_body", "Something went wrong"),
    ("LeetCode",     "https://leetcode.com/{}",                 "not_found_in_body", "404"),
    ("Kaggle",       "https://www.kaggle.com/{}",               "not_found_in_body", "Page not found"),
    ("Replit",       "https://replit.com/@{}",                  "not_found_in_body", "404"),
    ("CodePen",      "https://codepen.io/{}",                   "status",  None),
    ("NPM",          "https://www.npmjs.com/~{}",               "not_found_in_body", "404"),
]


def check_platform(name, url_template, mode, marker, username):
    url = url_template.format(username)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return (name, url, 'blocked')  # network error/timeout — can't verify, not a "not found"

    if resp.status_code in BLOCKED_STATUS_CODES:
        return (name, url, 'blocked')

    if mode == "status":
        exists = resp.status_code == 200
    elif mode == "not_found_in_body":
        exists = resp.status_code == 200 and marker not in resp.text
    else:
        exists = False

    return (name, url, 'found' if exists else 'not_found')


def main():
    if len(sys.argv) < 2:
        print("Error: No username provided")
        sys.exit(1)

    username = sys.argv[1]
    found, blocked = [], []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(check_platform, name, url_template, mode, marker, username)
            for name, url_template, mode, marker in PLATFORMS
        ]
        for future in as_completed(futures):
            name, url, status = future.result()
            if status == 'found':
                found.append((name, url))
            elif status == 'blocked':
                blocked.append(name)

    print(f"Username: {username}")
    print(f"Platforms Checked: {len(PLATFORMS)}")
    print(f"Profiles Found: {len(found)}")

    if found:
        for name, url in sorted(found):
            print(f"{name}: {url}")
    else:
        print("Result: No confirmed matching profiles found.")

    if blocked:
        print(f"Could Not Verify (anti-bot protection): {', '.join(sorted(blocked))}")


if __name__ == "__main__":
    main()