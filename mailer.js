// mailer.js — Envoi d'email pour NUNI (code d'accès envoyé à l'admin après activation)
const nodemailer = require('nodemailer');

// Le transporteur est créé une seule fois et réutilisé.
// Utilise un compte Gmail : EMAIL_USER = nunimisiki@gmail.com, EMAIL_APP_PASSWORD = mot de passe d'application Gmail.
let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (!process.env.EMAIL_USER || !process.env.EMAIL_APP_PASSWORD) {
    console.warn('[mailer] EMAIL_USER / EMAIL_APP_PASSWORD manquants — l\'envoi d\'email est désactivé.');
    return null;
  }
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_APP_PASSWORD,
    },
  });
  return transporter;
}

const PLAN_LABELS = {
  consumer: 'Pass Consommateur',
  artist: 'Pass Artiste',
  discovery: 'Pass Découverte',
};

// Envoie le code d'accès généré à l'adresse email NUNI (process.env.EMAIL_USER),
// pour que l'admin puisse ensuite le retransmettre au client sur WhatsApp.
async function sendAccessCodeEmail({ user, plan, accessCode, durationDays }) {
  const t = getTransporter();
  if (!t) return { sent: false, reason: 'email_not_configured' };

  const planLabel = PLAN_LABELS[plan] || plan;
  const to = process.env.EMAIL_USER;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <h2 style="color:#0E3D2C;">Nouveau code d'accès NUNI généré</h2>
      <p>Un abonnement vient d'être activé. Voici le code à transmettre au client sur WhatsApp :</p>
      <div style="background:#0E3D2C; color:#E8C77E; font-size:28px; font-weight:bold; letter-spacing:4px; text-align:center; padding:16px; border-radius:8px; margin:16px 0;">
        ${accessCode}
      </div>
      <table style="width:100%; border-collapse: collapse; font-size:14px;">
        <tr><td style="padding:4px 0; color:#666;">Client</td><td style="padding:4px 0;"><b>${user.first_name} ${user.last_name}</b></td></tr>
        <tr><td style="padding:4px 0; color:#666;">Email</td><td style="padding:4px 0;">${user.email}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Téléphone</td><td style="padding:4px 0;">${user.phone || '—'}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Pass</td><td style="padding:4px 0;">${planLabel}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Durée</td><td style="padding:4px 0;">${durationDays} jours</td></tr>
      </table>
      <p style="margin-top:20px; color:#888; font-size:12px;">NUNI — La musique congolaise mérite son envol.</p>
    </div>
  `;

  try {
    await t.sendMail({
      from: `"NUNI" <${process.env.EMAIL_USER}>`,
      to,
      subject: `🔑 Code d'accès NUNI pour ${user.first_name} ${user.last_name} : ${accessCode}`,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] Échec envoi email :', err.message);
    return { sent: false, reason: err.message };
  }
}

// Envoie le code de réinitialisation directement au CLIENT (contrairement à
// sendAccessCodeEmail, qui va toujours vers la boîte NUNI) — c'est lui qui a demandé
// à réinitialiser son mot de passe, donc c'est à son adresse qu'on répond.
async function sendPasswordResetEmail({ user, resetCode }) {
  const t = getTransporter();
  if (!t) return { sent: false, reason: 'email_not_configured' };

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <h2 style="color:#0E3D2C;">Réinitialisation de votre mot de passe NUNI</h2>
      <p>Bonjour ${user.first_name},</p>
      <p>Voici votre code pour réinitialiser votre mot de passe. Il est valable 15 minutes.</p>
      <div style="background:#0E3D2C; color:#E8C77E; font-size:28px; font-weight:bold; letter-spacing:8px; text-align:center; padding:16px; border-radius:8px; margin:16px 0;">
        ${resetCode}
      </div>
      <p style="color:#888; font-size:13px;">Si vous n'êtes pas à l'origine de cette demande, ignorez simplement cet email — votre mot de passe restera inchangé.</p>
      <p style="margin-top:20px; color:#888; font-size:12px;">NUNI — La musique congolaise mérite son envol.</p>
    </div>
  `;

  try {
    await t.sendMail({
      from: `"NUNI" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: `🔑 Votre code de réinitialisation NUNI : ${resetCode}`,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] Échec envoi email de réinitialisation :', err.message);
    return { sent: false, reason: err.message };
  }
}

async function sendAdRequestEmail({ name, desc, link, contact, duration }) {
  const t = getTransporter();
  if (!t) return { sent: false, reason: 'email_not_configured' };
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <h2 style="color:#0E3D2C;">Nouvelle demande de publicité NUNI</h2>
      <table style="width:100%; border-collapse: collapse; font-size:14px;">
        <tr><td style="padding:4px 0; color:#666;">Produit / marque</td><td style="padding:4px 0;"><b>${name}</b></td></tr>
        <tr><td style="padding:4px 0; color:#666;">Description</td><td style="padding:4px 0;">${desc || '—'}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Lien</td><td style="padding:4px 0;">${link}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Contact</td><td style="padding:4px 0;">${contact}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Durée souhaitée</td><td style="padding:4px 0;">${duration || '—'}</td></tr>
      </table>
      <p style="margin-top:20px; color:#888; font-size:12px;">NUNI — La musique congolaise mérite son envol.</p>
    </div>
  `;
  try {
    await t.sendMail({ from: `"NUNI" <${process.env.EMAIL_USER}>`, to: process.env.EMAIL_USER, subject: `Nouvelle demande de publicité : ${name}`, html });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] Échec envoi email de demande de publicité :', err.message);
    return { sent: false, reason: err.message };
  }
}

// Notifie l'artiste par email quand un paiement lui est versé — trace écrite en dehors de
// la plateforme, utile pour ses propres comptes.
async function sendArtistPaymentEmail({ user, amountFcfa, streamsCovered, periodStart, periodEnd }) {
  const t = getTransporter();
  if (!t) return { sent: false, reason: 'email_not_configured' };
  const fmtDate = (d) => d ? new Date(d).toLocaleDateString('fr-FR') : '—';
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <h2 style="color:#0E3D2C;">Versement NUNI effectué</h2>
      <p>Bonjour ${user.first_name},</p>
      <p>Un versement vient d'être enregistré sur votre compte NUNI :</p>
      <div style="background:#0E3D2C; color:#E8C77E; font-size:26px; font-weight:bold; text-align:center; padding:16px; border-radius:8px; margin:16px 0;">
        ${amountFcfa.toLocaleString('fr-FR')} FCFA
      </div>
      <table style="width:100%; border-collapse: collapse; font-size:14px;">
        <tr><td style="padding:4px 0; color:#666;">Streams couverts</td><td style="padding:4px 0;">${streamsCovered.toLocaleString('fr-FR')}</td></tr>
        <tr><td style="padding:4px 0; color:#666;">Période</td><td style="padding:4px 0;">${fmtDate(periodStart)} → ${fmtDate(periodEnd)}</td></tr>
      </table>
      <p style="margin-top:20px; color:#888; font-size:12px;">NUNI — La musique congolaise mérite son envol.</p>
    </div>
  `;
  try {
    await t.sendMail({ from: `"NUNI" <${process.env.EMAIL_USER}>`, to: user.email, subject: `Versement NUNI : ${amountFcfa.toLocaleString('fr-FR')} FCFA`, html });
    return { sent: true };
  } catch (err) {
    console.error('[mailer] Échec envoi email de versement :', err.message);
    return { sent: false, reason: err.message };
  }
}

module.exports = { sendAccessCodeEmail, sendPasswordResetEmail, sendAdRequestEmail, sendArtistPaymentEmail };
