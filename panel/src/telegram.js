// Minimal Telegram bot: notifies the admin and answers a few commands about the panel.
// Uses long-poll-free webhooks (Telegram calls our Worker), so there is no background process.
const API = (token) => `https://api.telegram.org/bot${token}`;

async function call(token, method, body) {
  const res = await fetch(`${API(token)}/${method}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!data.ok) throw new Error(data.description || `Telegram ${method} failed`);
  return data.result;
}

export const sendMessage = (token, chatId, text, extra = {}) =>
  call(token, 'sendMessage', { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true, ...extra });

export async function setWebhook(token, url, secret) {
  return call(token, 'setWebhook', { url, secret_token: secret, allowed_updates: ['message'], drop_pending_updates: true });
}
export const deleteWebhook = (token) => call(token, 'deleteWebhook', { drop_pending_updates: true });
export const getMe = (token) => call(token, 'getMe', {});

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const HELP =
  '<b>Dart Panel bot</b>\n\n' +
  '/status — is the panel online\n' +
  '/links — subscription links\n' +
  '/newsub — replace the subscription link (old one stops working)\n' +
  '/help — this message';

async function reply(token, chatId, text, extra) {
  try { await sendMessage(token, chatId, text, extra); } catch { /* best effort */ }
}

// Only the chat that was linked from the panel may use the bot.
function authorized(update, settings) {
  const chatId = update.message?.chat?.id;
  return chatId && String(chatId) === String(settings.telegram.chatId) ? chatId : null;
}

export async function handleUpdate(update, env, settings, ctx) {
  const token = settings.telegram.token;
  const text = (update.message?.text || '').trim();
  const chatId = update.message?.chat?.id;

  // Linking flow: /start <linkCode> from the chat the owner wants notifications in.
  if (text.startsWith('/start')) {
    const code = text.split(/\s+/)[1];
    const pending = code && (await env.kv.get(`tg-link:${code}`));
    if (!pending) return reply(token, chatId, 'This link code is invalid or expired. Generate a new one from the panel.');
    await env.kv.delete(`tg-link:${code}`);
    await ctx.saveTelegram({ ...settings.telegram, chatId: String(chatId) });
    return reply(token, chatId, `Linked. This chat will get notifications for <b>${esc(settings.configName)}</b>.\n\n${HELP}`);
  }

  const chat = authorized(update, settings);
  if (!chat) return; // ignore messages from anyone not linked

  if (text.startsWith('/status')) {
    return reply(token, chat, `🟢 Online\nProtocols: ${[settings.protocols.vless && 'VLESS', settings.protocols.trojan && 'Trojan'].filter(Boolean).join(', ')}`);
  }
  if (text.startsWith('/links')) {
    const lines = ctx.subs.map((s) => `<b>${esc(s.label)}</b>\n${esc(s.url)}`).join('\n\n');
    return reply(token, chat, lines);
  }
  if (text.startsWith('/newsub')) {
    const next = await ctx.regenerateSub();
    return reply(token, chat, `New subscription link:\n${esc(next)}`);
  }
  return reply(token, chat, HELP);
}

export const notifyPasswordChanged = (token, chatId) => reply(token, chatId, '🔒 Your Dart Panel password was changed.');
