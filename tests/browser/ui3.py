import asyncio, urllib.parse, time
from playwright.async_api import async_playwright
import os; S=os.environ.get("VC_TMP", "/tmp/vc-browser")
ONE='<form><input name="email" type="email"><input name="password" type="password"></form>'
TWO='<form><input name="identifier" type="text"><input id=pw name="password" type="password" style="display:none"></form>'
OTP='<form><input name="user"><input name="pass" type="password"><input name="otp" autocomplete="one-time-code"></form>'
PAGES={"/one":ONE,"/two":TWO,"/otp":OTP}
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        hosts=["https://login.example.com","https://evil.test"]
        ctx = await b.new_context(accept_downloads=True)
        await ctx.grant_permissions(["clipboard-read","clipboard-write"])
        for h in hosts: await ctx.grant_permissions(["clipboard-read","clipboard-write"], origin=h)
        async def handler(route):
            u=urllib.parse.urlparse(route.request.url)
            await route.fulfill(status=200, content_type="text/html", body="<html><body>"+PAGES.get(u.path,ONE)+"</body></html>")
        for h in hosts: await ctx.route(h+"/**", handler)
        app = await ctx.new_page()
        errs=[]
        app.on("pageerror", lambda e: errs.append(str(e)))
        await app.goto("file://" + os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dist")) + "/vault-convert.html")
        await app.set_input_files("#file-input", S+"/test.kdbx")
        await app.fill("input[name=password]","hunter2 pw"); await app.click("#cred-form button[type=submit]")
        await app.wait_for_selector("tr[data-row]")
        await app.click("[data-action=autofill]")
        href = await app.get_attribute("#bm-link","href")
        code = urllib.parse.unquote(href[len("javascript:"):])
        print("bookmarklet chars:", len(code), "self-contained:", "import" not in code)
        await app.click("#modal [data-action=modal-close]")
        async def fill_packet(name):
            await app.click(f"tr[data-row]:has-text('{name}') [data-action=fill]")
            await app.wait_for_timeout(100)
        async def run(url, setup=None):
            pg = await ctx.new_page()
            dialogs=[]
            async def on_dialog(d): dialogs.append(d.message[:60]); await d.dismiss()
            pg.on("dialog", on_dialog)
            await pg.goto(url)
            if setup: await setup(pg)
            await pg.evaluate(code)
            await pg.wait_for_timeout(600)
            vals = await pg.evaluate("[...document.querySelectorAll('input')].map(i=>i.name+'='+i.value)")
            msg = await pg.evaluate("[...document.querySelectorAll('[role=status]')].map(d=>d.textContent)")
            return pg, vals, msg, dialogs
        # A: matching one-step
        await fill_packet("Example")
        pg, vals, msg, dl = await run("https://login.example.com/one")
        print("A match:", vals, msg, dl)
        clip = await pg.evaluate("navigator.clipboard.readText()")
        print("A clipboard after fill:", repr(clip))
        # B: two-step
        await fill_packet("Example")
        pg, vals, msg, dl = await run("https://login.example.com/two")
        print("B step1:", vals, msg)
        clip = await pg.evaluate("navigator.clipboard.readText()")
        print("B clipboard kept after username-only:", clip.startswith("VCFILL1."))
        await pg.evaluate("document.getElementById('pw').style.display='block'")
        await pg.evaluate(code); await pg.wait_for_timeout(600)
        print("B step2:", await pg.evaluate("[...document.querySelectorAll('input')].map(i=>i.name+'='+i.value)"))
        # C: mismatch
        await fill_packet("Example")
        pg, vals, msg, dl = await run("https://evil.test/one")
        print("C mismatch:", vals, dl)
        # D: expired
        await app.evaluate("""async()=>{const t=VCFILL=>0; }""") if False else None
        await app.evaluate("""async()=>{const o={h:['login.example.com'],u:'x',p:'y',t:'',ts:Date.now()-200000};
          const b=btoa(JSON.stringify(o)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
          await navigator.clipboard.writeText('VCFILL1.'+b);}""")
        pg, vals, msg, dl = await run("https://login.example.com/one")
        print("D expired:", vals, msg)
        # E: nothing on clipboard
        await app.evaluate("navigator.clipboard.writeText('hello')")
        pg, vals, msg, dl = await run("https://login.example.com/one")
        print("E none:", vals, msg)
        # F: totp
        await fill_packet("Example")
        pg, vals, msg, dl = await run("https://login.example.com/otp")
        print("F totp:", vals, msg)
        # G: Other (host other.test) on login.example.com => mismatch
        await fill_packet("Other")
        pg, vals, msg, dl = await run("https://login.example.com/one")
        print("G other-login on wrong site:", vals, dl)
        print("errs", errs)
        await b.close()
asyncio.run(main())
