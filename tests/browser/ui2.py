import asyncio, base64, json, urllib.parse
from playwright.async_api import async_playwright
import os; S=os.environ.get("VC_TMP", "/tmp/vc-browser")
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        ctx = await b.new_context(permissions=["clipboard-read","clipboard-write"], accept_downloads=True)
        await ctx.add_init_script("delete window.showOpenFilePicker; delete window.showSaveFilePicker;")
        page = await ctx.new_page()
        errs=[]
        page.on("console", lambda m: errs.append(m.text) if m.type=="error" else None)
        page.on("pageerror", lambda e: errs.append("PAGEERR "+str(e)+" "+str(e.stack)[:600]))
        await page.goto("file://" + os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dist")) + "/vault-convert.html")
        await page.set_input_files("#file-input", S+"/test.kdbx")
        await page.fill("input[name=password]","hunter2 pw")
        await page.click("#cred-form button[type=submit]")
        await page.wait_for_selector("tr[data-row]")
        # edit + save (download fallback)
        await page.click("tr[data-row] >> text=Other")
        await page.click("[data-action=edit-start]")
        await page.fill("input[data-field=username]","bob-changed")
        await page.press("input[data-field=username]","Tab")
        async with page.expect_download() as dl:
            await page.click("[data-action=db-save]")
        d = await dl.value
        await d.save_as(S+"/saved.kdbx"); print("saved as", d.suggested_filename)
        # trash flow
        await page.click("[data-action=delete-item].btn.danger")
        await page.click("[data-action=modal-ok]")
        await page.click("button.nav[data-kind=trash]")
        print("trash rows", await page.locator("tr[data-row]").count())
        await page.click("button.nav[data-kind=all]")
        # encrypted export kdbx
        await page.click("[data-action=export].btn")
        await page.wait_for_selector("#enc-box", state="attached")
        print("enc box hidden for kdbx? ", await page.locator("#enc-box").is_hidden())
        await page.fill("#enc-pw","exp pass"); await page.fill("#enc-pw2","exp pass")
        async with page.expect_download() as dl:
            await page.click("#exp-download")
        d = await dl.value; await d.save_as(S+"/exported.kdbx"); print("export", d.suggested_filename)
        await page.click("input[name=fmt][value=bitwarden-encrypted]")
        await page.fill("#enc-pw","bw out"); await page.fill("#enc-pw2","bw out")
        async with page.expect_download() as dl:
            await page.click("#exp-download")
        d = await dl.value; await d.save_as(S+"/bw-out.json"); print("export", d.suggested_filename)
        await page.click("#modal [data-action=modal-close]")
        # import encrypted bitwarden
        await page.set_input_files("#file-input", S+"/bw-enc.json")
        await page.wait_for_selector("#cred-form")
        await page.fill("input[name=password]","bw pass")
        await page.click("#cred-form button[type=submit]")
        try:
            await page.wait_for_selector("#import-form", timeout=4000)
        except Exception:
            print("MODAL:", (await page.inner_text("#modal"))[:300], "ERRS", errs, "toasts", await page.locator(".toast").all_inner_texts()); raise
        print("import dialog:", (await page.inner_text("#modal .lede")))
        await page.click("#import-form button[type=submit]")
        await page.wait_for_timeout(300)
        print("rows now", await page.locator("tr[data-row] strong").all_inner_texts(), await page.locator(".toast").all_inner_texts(), await page.inner_text("#counts"))
        await page.screenshot(path=S+"/s4.png")
        print("errors:", errs)
        await b.close()
asyncio.run(main())
