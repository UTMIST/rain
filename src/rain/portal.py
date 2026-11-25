"""Small server-rendered views; Missing.css provides all styling."""

from html import escape

from fastapi.responses import HTMLResponse


def page(content, error="", status=200):
    notice = f'<p role="alert">{escape(error)}</p>' if error else ""
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Request access · Rain UTMIST</title>
<link rel="stylesheet" href="https://unpkg.com/missing.css@1.3.0/dist/missing.min.css"
  integrity="sha256-dm796XVi5T4DlJ9JjnTT4kvBsusZelB52j3WXHsOtFc=" crossorigin="anonymous">
<main>
  <h1>Request access to UTMIST Compute</h1>
  {notice}
  {content}
</main>
</html>""",
        status_code=status,
    )


def email_form(error="", status=200):
    return page(
        """
<img src="/ultrasonic-cleaner.png" width="425" height="340" alt="Stainless-steel ultrasonic cleaner with its lid open">
<p>Verify your Misty account to register an SSH key for UTMIST compute access.</p>
<form method="post" action="/request-code">
  <p><label>Misty email <input type="email" name="email" autocomplete="email" required></label></p>
  <button>Send verification code</button>
</form>""",
        error,
        status,
    )


def code_form(challenge_id, error="", status=200):
    return page(
        f"""
<p>Check your inbox for the verification code.</p>
<form method="post" action="/verify-code">
  <input type="hidden" name="challenge_id" value="{challenge_id}">
  <p><label>Verification code <input name="code" inputmode="numeric" autocomplete="one-time-code"
    pattern="[0-9]{{6}}" maxlength="6" required autofocus></label></p>
  <p><label>Full name (optional) <input name="name" autocomplete="name" maxlength="200"></label></p>
  <p><label>OpenSSH public key<br><textarea name="ssh_public_key" rows="3" maxlength="8192" required></textarea></label></p>
  <button>Verify and register key</button>
</form>
<p><a href="/">Request a new code</a></p>""",
        error,
        status,
    )


def approved(result, hostname):
    return page(f"""
<h2>SSH key registered</h2>
<dl>
  <dt>Person ID</dt><dd><code>{result.person_id}</code></dd>
  <dt>Cluster</dt><dd>{escape(result.cluster)}</dd>
  <dt>Slurm account</dt><dd>{escape(result.account)}</dd>
  <dt>Key fingerprint</dt><dd><code>{escape(result.ssh_key_fingerprint)}</code></dd>
</dl>
<p>Connect with <code>ssh {escape(result.slurm_username)}@{escape(hostname)}</code>.</p>
""")
