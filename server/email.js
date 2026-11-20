import { config } from "./config.js";

export class EmailDeliveryError extends Error {
  constructor(status) {
    super(`Resend rejected the email request with HTTP ${status}.`);
    this.name = "EmailDeliveryError";
    this.status = status;
  }
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

export async function sendPasswordResetEmail(to, resetUrl) {
  const url = escapeHtml(resetUrl.toString());
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: `Northstar Access <${config.passwordResetFromEmail}>`,
      to: [to],
      subject: "Reset your Northstar password",
      text: `A password reset was requested for your Northstar account.\n\nReset your password: ${resetUrl}\n\nThis link expires in 30 minutes. If you did not request this, you can ignore this email.`,
      html: `<p>A password reset was requested for your Northstar account.</p><p><a href="${url}">Reset your password</a></p><p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p>`,
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    throw new EmailDeliveryError(response.status);
  }
}
