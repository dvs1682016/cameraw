'use strict';
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client();
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ok:false,message:'只允許 POST'}); }
  try {
    const audience = process.env.GOOGLE_CLIENT_ID;
    const admin = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    if (!audience || !admin) return res.status(503).json({ok:false,message:'伺服器尚未設定登入驗證環境變數'});
    const token = req.body && typeof req.body.credential === 'string' ? req.body.credential : '';
    if (!token || token.length > 8192) return res.status(400).json({ok:false,message:'缺少有效登入憑證'});
    const ticket = await client.verifyIdToken({idToken:token,audience});
    const p = ticket.getPayload();
    if (!p || p.email_verified !== true || String(p.email || '').trim().toLowerCase() !== admin)
      return res.status(403).json({ok:false,message:'此 Google 帳號沒有管理員權限'});
    return res.status(200).json({ok:true,email:p.email,message:'管理員身分驗證成功。'});
  } catch (err) {
    return res.status(401).json({ok:false,message:'登入憑證無效或已過期，請重新登入。'});
  }
};
