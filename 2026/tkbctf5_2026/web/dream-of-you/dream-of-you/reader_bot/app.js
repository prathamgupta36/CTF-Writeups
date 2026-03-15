const express = require("express");
const puppeteer = require("puppeteer");

const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;

app.post("/report", async (req, res) => {
  const storyId = String(req.body?.id || "").trim();
  if (!/^[0-9]+$/.test(storyId)) {
    return res.status(400).send("invalid id");
  }

  const targetHost = "dream-of-you:5000";
  const flag = process.env.FLAG || "tkbctf{dummy}";
  const targetUrl = `http://${targetHost}/read/${storyId}`;
  const name = "Mahiru";

  try {
    const browser = await puppeteer.launch({
      headless: "new",
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    const page = await browser.newPage();

    await page.setCookie({
      name: "flag",
      value: flag,
      url: `http://${targetHost}/`,
      httpOnly: false,
      sameSite: "Strict",
    });

    await page.goto(targetUrl, { waitUntil: "networkidle2", timeout: 5000 });
    await page.waitForSelector("input[name='name']", { timeout: 3000 });
    await page.click("input[name='name']", { clickCount: 3 });
    await page.keyboard.type(name, { delay: 10 });
    await page.click("button[type='submit']");
    await new Promise(resolve => setTimeout(resolve, 1000));
    await browser.close();

    return res.status(200).send("ok");
  } catch (err) {
    console.error("reader bot error", err);
    return res.status(500).send("error");
  }
});

app.listen(port, () => {
  console.log(`reader bot listening on ${port}`);
});
