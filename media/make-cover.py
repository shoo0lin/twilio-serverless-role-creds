#!/usr/bin/env python3
"""Build the cover art for posts/twilio-trial-serverless.html.

Not a screenshot: the function's JSON response, reconstructed and drawn from
scratch. The key prefix is truncated exactly as it is in the post, and the one
boolean that decided the severity is the red line.
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 2000, 1125
BG = (5, 5, 5)
WHITE = (255, 255, 255)
GRAY = (199, 199, 199)
DIM = (102, 102, 102)
RED = (255, 0, 0)

MONO = "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf"
MONO_B = "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Bold.ttf"


def f(path, size):
    return ImageFont.truetype(path, size)


def tracked(draw, x, y, text, font, fill, spacing):
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        x += draw.textlength(ch, font=font) + spacing
    return x


def width_tracked(draw, text, font, spacing):
    return sum(draw.textlength(c, font=font) + spacing for c in text) - spacing


img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

kicker = f(MONO, 30)
body = f(MONO, 36)
big = f(MONO_B, 74)
value = f(MONO_B, 52)
small = f(MONO, 26)

# --- kicker ---------------------------------------------------------------
label = "TWILIO SERVERLESS  \u00b7  TRIAL ACCOUNT"
lx = (W - (width_tracked(d, label, kicker, 4) + 26)) // 2
d.rectangle([lx, 232, lx + 12, 244], fill=RED)
tracked(d, lx + 26, 220, label, kicker, WHITE, 4)

# --- the credential the environment handed back ---------------------------
line1 = "ASIAY2IZEHUX\u2026"
x1 = (W - d.textlength(line1, font=big)) // 2
d.text((x1, 296), line1, font=big, fill=WHITE)

line2 = "read from /proc/self/environ"
x2 = (W - d.textlength(line2, font=body)) // 2
d.text((x2, 404), line2, font=body, fill=GRAY)

# --- rule -----------------------------------------------------------------
d.line([W // 2 - 470, 478, W // 2 + 470, 478], fill=(45, 45, 45))

# --- the line that changed the score --------------------------------------
line3 = '"parent_token_present": false'
x3 = (W - d.textlength(line3, font=value)) // 2
d.text((x3, 512), line3, font=value, fill=RED)

l4 = '"aws_session_token": "present (1100 chars)"'
x4 = (W - d.textlength(l4, font=body)) // 2
d.text((x4, 612), l4, font=body, fill=GRAY)

l5 = '"aws_log_group": "/aws/lambda/ZBeaf0U42\u2026"'
x5 = (W - d.textlength(l5, font=small)) // 2
d.text((x5, 682), l5, font=small, fill=DIM)

# --- what the credential actually reaches ---------------------------------
note = ("sts:GetCallerIdentity \u2192 606179966…  \u00b7  "
        "lambda-role-execution  \u00b7  its own logs")
xn = (W - d.textlength(note, font=small)) // 2
d.text((xn, 770), note, font=small, fill=DIM)

# --- footnote -------------------------------------------------------------
foot = "no card  \u00b7  no upgrade  \u00b7  one deploy  \u00b7  4.3, not 9.9"
xf = (W - d.textlength(foot, font=small)) // 2
d.text((xf, 846), foot, font=small, fill=(116, 116, 116))

img.save("/root/Docue/ppp/shoo0lin.github.io/assets/img/twilio/00-cover-twilio.png")
print("written")
