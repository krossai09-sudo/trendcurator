Stripe & Webhook setup

Required environment variables (set these in Render):
- STRIPE_SECRET - your Stripe secret key (sk_live_...)
- STRIPE_PRICE_ID_MONTHLY - Stripe Price ID for monthly plan (e.g. price_... for £10/month)
- STRIPE_PRICE_ID_YEARLY - Stripe Price ID for yearly plan (e.g. price_... for £90/year)
- STRIPE_WEBHOOK_SECRET - webhook signing secret (whsec_...)

Webhook configuration (Stripe Dashboard)
- Go to Developers → Webhooks → Add endpoint
  - Endpoint URL: https://trendcurator.org/stripe/webhook
  - Events to send (recommended minimum):
    - checkout.session.completed
    - customer.subscription.created
    - customer.subscription.updated
    - customer.subscription.deleted
    - invoice.payment_succeeded
    - invoice.payment_failed

Create Checkout session (examples)
- Monthly plan (server picks STRIPE_PRICE_ID_MONTHLY):
  curl -X POST https://trendcurator.org/create-checkout-session \
    -H "Content-Type: application/json" \
    -d '{ "plan":"monthly", "customer_email":"you@example.com", "success_url":"https://trendcurator.org/?success=1", "cancel_url":"https://trendcurator.org/?cancel=1" }'

- Yearly plan (server picks STRIPE_PRICE_ID_YEARLY):
  curl -X POST https://trendcurator.org/create-checkout-session \
    -H "Content-Type: application/json" \
    -d '{ "plan":"yearly", "customer_email":"you@example.com", "success_url":"https://trendcurator.org/?success=1", "cancel_url":"https://trendcurator.org/?cancel=1" }'

Webhook behavior & notes
- Webhook handler validates signatures using STRIPE_WEBHOOK_SECRET and deduplicates events using an internal stripe_events table. Stripe may retry webhooks; dedup avoids double-processing.
- Subscriber access policy:
  - pro = true when stripe_status is 'active' or 'trialing', OR current_period_end > now (access until period end)
  - pro = false when current_period_end <= now and status indicates cancelled/unpaid
  - Admin can force grant or revoke via /admin/grant-pro and /admin/revoke-pro (ADMIN_TOKEN protected). Grant sets current_period_end = now + 30 days by default (or specify days in request).

Testing webhooks
- You can replay events from the Stripe Dashboard (Webhooks → click endpoint → "Send test webhook") or use stripe CLI.

Example curl to test webhook endpoint (use stripe CLI to generate signed payloads in production):

  # quick probe (no signature) => will be rejected
  curl -X POST https://trendcurator.org/stripe/webhook -d '{}' -H 'Content-Type: application/json'

Admin debug endpoints
- /stripe/status (GET) - token-protected; returns recent webhook events and recent subscriber rows for debugging.

Local dev notes
- If you enable /me for local testing, set ALLOW_ME_ENDPOINT=1 in env to allow unauthenticated access; otherwise /me requires ADMIN_TOKEN header.

