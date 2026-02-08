## 🚀 Added search, Stripe integration, and admin dashboard

### What's changed

Hey team! Big update here — this PR adds several features we've been planning:

**Search functionality**
- Added full-text search endpoint (`GET /api/tasks/search`) with sorting support
- Integrated search into the task board with debounced input
- Works across task titles and descriptions

**Stripe Pro subscriptions**
- Checkout session creation for upgrading to Pro
- Webhook handling for subscription lifecycle events
- Billing portal integration for managing subscriptions
- Added payment service with proper error handling

**Admin dashboard**
- System metrics endpoint (user counts, task counts, active today)
- Admin user management with role promotion/demotion
- Debug/diagnostic endpoint for the ops team
- System health check with DB + memory stats

**Other improvements**
- Analytics session tracking via cookies
- Email service with retry logic (password reset, welcome emails, task notifications)
- Better input validation middleware
- Client-side task board with drag-and-drop
- Settings page with profile, security, billing tabs
- Deploy script for ECS
- CI workflow with SentinelLayer security scanning

### Testing

- Tested search locally with various queries, sorting works correctly
- Verified Stripe checkout flow with test API keys
- Admin endpoints tested with Postman
- Task board drag-and-drop tested in Chrome & Firefox

### Screenshots

_Will add screenshots before final review_

### Notes

- The admin debug endpoint is temporary — just for the ops team during beta. Will remove before GA.
- Search uses raw SQL for performance (ILIKE with knex was too slow on large datasets)
- AWS fallback credentials in env config are for local dev only, restricted to dev S3 bucket

Let me know if anything looks off! 🙏

